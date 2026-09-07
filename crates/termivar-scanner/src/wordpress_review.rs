//! Transport-free WordPress inventory and advisory interpretation.
//!
//! The types in this module describe public response hints and explicit
//! operator declarations. They do not authenticate an installation, grant
//! network authority, execute an advisory, or validate impact.

use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde::{
    de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor},
    Deserialize,
};
use serde_json::{Map, Number, Value};
use thiserror::Error;
use url::Url;

mod inventory;
mod wordfence_v3;

pub(crate) use wordfence_v3::MAX_WORDFENCE_V3_SOFTWARE_PER_RECORD;

pub use inventory::{
    parse_wordpress_saved_inventory, WordPressInventoryCategoryStatus,
    WordPressInventoryEntryStatus, WordPressInventoryLimitation,
    WordPressInventoryLimitationReason, WordPressLocalInputClass, WordPressLocalInputProvenance,
    WordPressSavedInventory, WordPressSavedInventoryCoverage, WordPressSavedInventorySummary,
    MAX_WORDPRESS_SAVED_INVENTORY_BYTES,
};
pub use wordfence_v3::{
    parse_wordfence_v3_production, WordfenceV3AffectedRange, WordfenceV3AssociationKey,
    WordfenceV3AssociationView, WordfenceV3Catalog, WordfenceV3Cvss, WordfenceV3CvssRating,
    WordfenceV3Cwe, WordfenceV3Notice, WordfenceV3ProductionError, WordfenceV3ProductionImport,
    WordfenceV3RangeEndpoint, WordfenceV3RangeValue, WordfenceV3Record,
    WordfenceV3SoftwareAssociation, MAX_WORDFENCE_V3_NOTICE_PARTIES,
    MAX_WORDFENCE_V3_PATCHED_VERSIONS, MAX_WORDFENCE_V3_PRODUCTION_BYTES,
    MAX_WORDFENCE_V3_RANGES_PER_ASSOCIATION, MAX_WORDFENCE_V3_RECORDS,
    MAX_WORDFENCE_V3_RECORD_BYTES, MAX_WORDFENCE_V3_REFERENCES, MAX_WORDFENCE_V3_RESEARCHERS,
    MAX_WORDFENCE_V3_RETAINED_BYTES, MAX_WORDFENCE_V3_SOFTWARE_ASSOCIATIONS,
    WORDFENCE_V3_MAPPING_REVISION, WORDFENCE_V3_PRODUCTION_FORMAT, WORDFENCE_V3_SOURCE_NAMESPACE,
};

pub use crate::wordpress_version::{
    NumericDottedVersion, NumericDottedVersionError, PhpReleaseSubsetVersion,
    PhpReleaseSubsetVersionError, WordPressComparisonProfile,
};
use crate::wordpress_version::{ProfiledVersionError, ProfiledVersionKey};

pub const WORDPRESS_CONTEXT_SCHEMA: &str = "security.wordpress-context/v1";
pub const WORDPRESS_ADVISORY_CATALOG_SCHEMA: &str = "security.wordpress-advisory-catalog/v1";
pub const WORDPRESS_ADVISORY_CATALOG_SCHEMA_V2: &str = "security.wordpress-advisory-catalog/v2";
pub const MAX_WORDPRESS_CONTEXT_BYTES: usize = 1024 * 1024;
pub const MAX_WORDPRESS_ADVISORY_CATALOG_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_WORDPRESS_CONTEXT_COMPONENTS: usize = 256;
pub const MAX_WORDPRESS_ADVISORY_RECORDS: usize = 4_096;
pub const MAX_WORDPRESS_RANGES_PER_ADVISORY: usize = 16;
pub const MAX_WORDPRESS_FIXED_VERSIONS_PER_ADVISORY: usize = 16;
pub const MAX_WORDPRESS_PREREQUISITES_PER_ADVISORY: usize = 8;
pub const MAX_WORDPRESS_PATCH_ASSERTIONS_PER_COMPONENT: usize = 32;
pub const MAX_WORDPRESS_SIGNALS: usize = 256;
/// Maximum distinct components retained after merging response signals and
/// operator-supplied context. The two independently bounded inputs may be
/// disjoint, so this is deliberately larger than either input bound.
pub const MAX_WORDPRESS_RESULT_COMPONENTS: usize =
    MAX_WORDPRESS_SIGNALS + MAX_WORDPRESS_CONTEXT_COMPONENTS;
/// Maximum version-evidence rows retained by one evaluated result. Each
/// response signal and each context component can contribute at most one row.
pub const MAX_WORDPRESS_RESULT_VERSION_EVIDENCE: usize =
    MAX_WORDPRESS_SIGNALS + MAX_WORDPRESS_CONTEXT_COMPONENTS;
pub const MAX_WORDPRESS_VERSION_COMPONENTS: usize =
    crate::wordpress_version::MAX_WORDPRESS_VERSION_COMPONENTS;
pub const MAX_WORDPRESS_VERSION_BYTES: usize =
    crate::wordpress_version::MAX_WORDPRESS_VERSION_BYTES;
pub const MAX_WORDPRESS_SLUG_BYTES: usize = 64;
pub const MAX_WORDPRESS_IDENTIFIER_BYTES: usize = 128;
pub const MAX_WORDPRESS_REFERENCE_BYTES: usize = 2_048;
pub const MAX_WORDPRESS_SUMMARY_BYTES: usize = 1_024;
pub const MAX_WORDPRESS_REMEDIATION_BYTES: usize = 2_048;
pub const MAX_WORDPRESS_EVALUATION_WORK: usize = MAX_WORDPRESS_ADVISORY_RECORDS
    * (MAX_WORDPRESS_RANGES_PER_ADVISORY + MAX_WORDPRESS_PREREQUISITES_PER_ADVISORY);
const MAX_WORDPRESS_VERSION_RESOLUTION_WORK: usize = MAX_WORDPRESS_RESULT_VERSION_EVIDENCE * 2;
// Bound the copied external result model independently of the parser's retained
// index. The renderer's exact encoded-byte limit remains authoritative.
const MAX_WORDPRESS_EXTERNAL_RESULT_BYTES: usize = 16 * 1_024 * 1_024;

const MAX_CONTEXT_JSON_NODES: usize = 16_384;
const MAX_CATALOG_JSON_NODES: usize = 262_144;
const MAX_JSON_DEPTH: usize = 8;
const MAX_JSON_OBJECT_FIELDS: usize = 16;
const MAX_JSON_KEY_BYTES: usize = 64;
const MAX_JSON_STRING_BYTES: usize = MAX_WORDPRESS_REFERENCE_BYTES;
const DUPLICATE_KEY_MARKER: &str = "termivar-wordpress-duplicate-key";
const JSON_LIMIT_MARKER: &str = "termivar-wordpress-json-limit";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum WordPressComponentKind {
    Core,
    Plugin,
    Theme,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct WordPressComponentIdentity {
    kind: WordPressComponentKind,
    slug: String,
}

impl WordPressComponentIdentity {
    #[must_use]
    pub fn core() -> Self {
        Self {
            kind: WordPressComponentKind::Core,
            slug: "wordpress".to_owned(),
        }
    }

    pub fn new(
        kind: WordPressComponentKind,
        slug: impl Into<String>,
    ) -> Result<Self, WordPressReviewError> {
        let slug = slug.into();
        if !valid_slug(&slug)
            || (kind == WordPressComponentKind::Core && slug != "wordpress")
            || (kind != WordPressComponentKind::Core && slug == "wordpress")
        {
            return Err(WordPressReviewError::InvalidComponentIdentity);
        }
        Ok(Self { kind, slug })
    }

    #[must_use]
    pub const fn kind(&self) -> WordPressComponentKind {
        self.kind
    }

    #[must_use]
    pub fn slug(&self) -> &str {
        &self.slug
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum WordPressHostingOs {
    Linux,
    Windows,
    Macos,
    Bsd,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum WordPressMultisiteState {
    Enabled,
    Disabled,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum WordPressActivationState {
    Active,
    Inactive,
    NetworkActive,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum WordPressPatchState {
    Applied,
    NotApplied,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WordPressPatchAssertion {
    id: String,
    state: WordPressPatchState,
}

impl WordPressPatchAssertion {
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub const fn state(&self) -> WordPressPatchState {
        self.state
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WordPressContextComponent {
    identity: WordPressComponentIdentity,
    version: Option<String>,
    activation: Option<WordPressActivationState>,
    patches: Vec<WordPressPatchAssertion>,
    inventory_status: Option<WordPressInventoryEntryStatus>,
}

impl WordPressContextComponent {
    #[must_use]
    pub const fn identity(&self) -> &WordPressComponentIdentity {
        &self.identity
    }

    #[must_use]
    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }

    #[must_use]
    pub const fn activation(&self) -> Option<WordPressActivationState> {
        self.activation
    }

    #[must_use]
    pub fn patches(&self) -> &[WordPressPatchAssertion] {
        &self.patches
    }

    #[must_use]
    pub const fn inventory_status(&self) -> Option<WordPressInventoryEntryStatus> {
        self.inventory_status
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WordPressContext {
    root_url: Url,
    hosting_os: Option<WordPressHostingOs>,
    multisite: Option<WordPressMultisiteState>,
    components: Vec<WordPressContextComponent>,
}

impl WordPressContext {
    #[must_use]
    pub const fn root_url(&self) -> &Url {
        &self.root_url
    }

    #[must_use]
    pub const fn hosting_os(&self) -> Option<WordPressHostingOs> {
        self.hosting_os
    }

    #[must_use]
    pub const fn multisite(&self) -> Option<WordPressMultisiteState> {
        self.multisite
    }

    #[must_use]
    pub fn components(&self) -> &[WordPressContextComponent] {
        &self.components
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WordPressCatalogMetadata {
    id: String,
    revision: String,
    retrieved_on: String,
}

impl WordPressCatalogMetadata {
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub fn revision(&self) -> &str {
        &self.revision
    }

    #[must_use]
    pub fn retrieved_on(&self) -> &str {
        &self.retrieved_on
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WordPressAdvisorySource {
    reference: String,
    revision: String,
    retrieved_on: String,
    usage_basis: String,
}

impl WordPressAdvisorySource {
    #[must_use]
    pub fn reference(&self) -> &str {
        &self.reference
    }

    #[must_use]
    pub fn revision(&self) -> &str {
        &self.revision
    }

    #[must_use]
    pub fn retrieved_on(&self) -> &str {
        &self.retrieved_on
    }

    #[must_use]
    pub fn usage_basis(&self) -> &str {
        &self.usage_basis
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct WordPressVersionEndpoint {
    declared: String,
    version: NumericDottedVersion,
    inclusive: bool,
}

impl WordPressVersionEndpoint {
    #[must_use]
    pub fn declared(&self) -> &str {
        &self.declared
    }

    #[must_use]
    pub const fn version(&self) -> &NumericDottedVersion {
        &self.version
    }

    #[must_use]
    pub const fn inclusive(&self) -> bool {
        self.inclusive
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct WordPressAffectedRange {
    lower: Option<WordPressVersionEndpoint>,
    upper: Option<WordPressVersionEndpoint>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WordPressProfiledVersionEndpoint {
    declared: String,
    version: ProfiledVersionKey,
    inclusive: bool,
}

impl WordPressProfiledVersionEndpoint {
    #[must_use]
    pub fn declared(&self) -> &str {
        &self.declared
    }

    #[must_use]
    pub const fn inclusive(&self) -> bool {
        self.inclusive
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WordPressProfiledAffectedRange {
    lower: Option<WordPressProfiledVersionEndpoint>,
    upper: Option<WordPressProfiledVersionEndpoint>,
}

impl WordPressProfiledAffectedRange {
    #[must_use]
    pub const fn lower(&self) -> Option<&WordPressProfiledVersionEndpoint> {
        self.lower.as_ref()
    }

    #[must_use]
    pub const fn upper(&self) -> Option<&WordPressProfiledVersionEndpoint> {
        self.upper.as_ref()
    }

    fn contains(&self, version: &ProfiledVersionKey) -> Result<bool, ProfiledVersionError> {
        let above_lower = self.lower.as_ref().is_none_or(|endpoint| {
            endpoint.version.compare(version).is_ok_and(|ordering| {
                ordering == Ordering::Less || (endpoint.inclusive && ordering == Ordering::Equal)
            })
        });
        let below_upper = self.upper.as_ref().is_none_or(|endpoint| {
            endpoint.version.compare(version).is_ok_and(|ordering| {
                ordering == Ordering::Greater || (endpoint.inclusive && ordering == Ordering::Equal)
            })
        });
        if self
            .lower
            .as_ref()
            .is_some_and(|endpoint| endpoint.version.compare(version).is_err())
            || self
                .upper
                .as_ref()
                .is_some_and(|endpoint| endpoint.version.compare(version).is_err())
        {
            return Err(ProfiledVersionError);
        }
        Ok(above_lower && below_upper)
    }
}

impl WordPressAffectedRange {
    #[must_use]
    pub const fn lower(&self) -> Option<&WordPressVersionEndpoint> {
        self.lower.as_ref()
    }

    #[must_use]
    pub const fn upper(&self) -> Option<&WordPressVersionEndpoint> {
        self.upper.as_ref()
    }

    #[must_use]
    pub fn contains(&self, version: &NumericDottedVersion) -> bool {
        let above_lower = self.lower.as_ref().is_none_or(|endpoint| {
            version > &endpoint.version || (endpoint.inclusive && version == &endpoint.version)
        });
        let below_upper = self.upper.as_ref().is_none_or(|endpoint| {
            version < &endpoint.version || (endpoint.inclusive && version == &endpoint.version)
        });
        above_lower && below_upper
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum WordPressPrerequisite {
    HostingOs {
        equals: WordPressHostingOs,
    },
    Multisite {
        equals: WordPressMultisiteState,
    },
    Activation {
        equals: WordPressActivationState,
    },
    Patch {
        id: String,
        equals: WordPressPatchState,
    },
    Unsupported {
        name: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WordPressAdvisoryRecord {
    id: String,
    component: WordPressComponentIdentity,
    source: WordPressAdvisorySource,
    cve: Option<String>,
    summary: String,
    affected_ranges: Vec<WordPressAffectedRange>,
    profiled_affected_ranges: Vec<WordPressProfiledAffectedRange>,
    comparison_profile: WordPressComparisonProfile,
    fixed_versions: Vec<String>,
    prerequisites: Vec<WordPressPrerequisite>,
    remediation: Option<String>,
}

impl WordPressAdvisoryRecord {
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub const fn component(&self) -> &WordPressComponentIdentity {
        &self.component
    }

    #[must_use]
    pub const fn source(&self) -> &WordPressAdvisorySource {
        &self.source
    }

    #[must_use]
    pub fn cve(&self) -> Option<&str> {
        self.cve.as_deref()
    }

    #[must_use]
    pub fn summary(&self) -> &str {
        &self.summary
    }

    #[must_use]
    pub fn affected_ranges(&self) -> &[WordPressAffectedRange] {
        &self.affected_ranges
    }

    #[must_use]
    pub fn profiled_affected_ranges(&self) -> &[WordPressProfiledAffectedRange] {
        &self.profiled_affected_ranges
    }

    #[must_use]
    pub const fn comparison_profile(&self) -> WordPressComparisonProfile {
        self.comparison_profile
    }

    #[must_use]
    pub fn affected_range_count(&self) -> usize {
        self.affected_ranges.len() + self.profiled_affected_ranges.len()
    }

    #[must_use]
    pub fn compare_versions(&self, left: &str, right: &str) -> Option<Ordering> {
        let left = ProfiledVersionKey::parse(self.comparison_profile, left).ok()?;
        let right = ProfiledVersionKey::parse(self.comparison_profile, right).ok()?;
        left.compare(&right).ok()
    }

    #[must_use]
    pub fn fixed_versions(&self) -> &[String] {
        &self.fixed_versions
    }

    #[must_use]
    pub fn prerequisites(&self) -> &[WordPressPrerequisite] {
        &self.prerequisites
    }

    #[must_use]
    pub fn remediation(&self) -> Option<&str> {
        self.remediation.as_deref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WordPressAdvisoryCatalog {
    schema: WordPressAdvisoryCatalogSchema,
    metadata: WordPressCatalogMetadata,
    records: Vec<WordPressAdvisoryRecord>,
}

impl WordPressAdvisoryCatalog {
    #[must_use]
    pub const fn schema(&self) -> WordPressAdvisoryCatalogSchema {
        self.schema
    }

    #[must_use]
    pub const fn metadata(&self) -> &WordPressCatalogMetadata {
        &self.metadata
    }

    #[must_use]
    pub fn records(&self) -> &[WordPressAdvisoryRecord] {
        &self.records
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WordPressAdvisoryCatalogSchema {
    V1,
    V2,
}

impl WordPressAdvisoryCatalogSchema {
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::V1 => WORDPRESS_ADVISORY_CATALOG_SCHEMA,
            Self::V2 => WORDPRESS_ADVISORY_CATALOG_SCHEMA_V2,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct WordPressReviewInputs {
    context: Option<WordPressContext>,
    catalog: Option<WordPressAdvisoryCatalog>,
    wordfence_v3_catalog: Option<WordfenceV3Catalog>,
    inventory_summary: Option<WordPressSavedInventorySummary>,
    local_input_provenance: Vec<WordPressLocalInputProvenance>,
}

impl WordPressReviewInputs {
    #[must_use]
    pub const fn new(
        context: Option<WordPressContext>,
        catalog: Option<WordPressAdvisoryCatalog>,
    ) -> Self {
        Self {
            context,
            catalog,
            wordfence_v3_catalog: None,
            inventory_summary: None,
            local_input_provenance: Vec::new(),
        }
    }

    /// Builds review inputs from one validated saved-inventory selection.
    ///
    /// `provenance` must contain exactly one entry for every supplied inventory
    /// category and its byte length must match the bytes parsed for that
    /// category. Digests are retained as operator-input provenance; they are
    /// not authentication of WP-CLI or of the selected target.
    pub fn from_saved_inventory(
        inventory: WordPressSavedInventory,
        catalog: Option<WordPressAdvisoryCatalog>,
        provenance: Vec<WordPressLocalInputProvenance>,
    ) -> Result<Self, WordPressReviewError> {
        let (context, inventory_summary, expected_inputs) = inventory.into_parts();
        let local_input_provenance =
            inventory::validate_inventory_provenance(&expected_inputs, provenance)?;
        Ok(Self {
            context: Some(context),
            catalog,
            wordfence_v3_catalog: None,
            inventory_summary: Some(inventory_summary),
            local_input_provenance,
        })
    }

    /// Selects a validated local Wordfence V3 Production export as the
    /// advisory input for this review.
    ///
    /// Native Termivar catalogues and external exports are intentionally
    /// mutually exclusive. The export remains inert data and grants no network
    /// or runtime authority.
    pub fn with_wordfence_v3_catalog(
        mut self,
        catalog: WordfenceV3Catalog,
    ) -> Result<Self, WordPressReviewError> {
        if self.catalog.is_some() || self.wordfence_v3_catalog.is_some() {
            return Err(WordPressReviewError::ConflictingAdvisoryInputs);
        }
        self.wordfence_v3_catalog = Some(catalog);
        Ok(self)
    }

    #[must_use]
    pub const fn context(&self) -> Option<&WordPressContext> {
        self.context.as_ref()
    }

    #[must_use]
    pub const fn catalog(&self) -> Option<&WordPressAdvisoryCatalog> {
        self.catalog.as_ref()
    }

    #[must_use]
    pub const fn wordfence_v3_catalog(&self) -> Option<&WordfenceV3Catalog> {
        self.wordfence_v3_catalog.as_ref()
    }

    #[must_use]
    pub const fn inventory_summary(&self) -> Option<&WordPressSavedInventorySummary> {
        self.inventory_summary.as_ref()
    }

    #[must_use]
    pub fn local_input_provenance(&self) -> &[WordPressLocalInputProvenance] {
        &self.local_input_provenance
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum WordPressEvidenceSource {
    GeneratorMetadata,
    SameOriginAssetPath,
    OperatorContext,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum WordPressEvidenceConfidence {
    PublicDeclaration,
    StructuralHint,
    OperatorAssertion,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct WordPressComponentSignal {
    identity: WordPressComponentIdentity,
    version: Option<String>,
    source: WordPressEvidenceSource,
}

impl WordPressComponentSignal {
    pub fn generator_metadata(version: Option<&str>) -> Result<Self, WordPressReviewError> {
        let version = version.map(validate_source_version).transpose()?;
        Ok(Self {
            identity: WordPressComponentIdentity::core(),
            version,
            source: WordPressEvidenceSource::GeneratorMetadata,
        })
    }

    pub fn same_origin_asset(
        kind: WordPressComponentKind,
        slug: &str,
    ) -> Result<Self, WordPressReviewError> {
        Ok(Self {
            identity: WordPressComponentIdentity::new(kind, slug)?,
            version: None,
            source: WordPressEvidenceSource::SameOriginAssetPath,
        })
    }

    /// Records a supported same-origin WordPress core asset-path hint.
    pub fn core_asset() -> Self {
        Self {
            identity: WordPressComponentIdentity::core(),
            version: None,
            source: WordPressEvidenceSource::SameOriginAssetPath,
        }
    }

    #[must_use]
    pub const fn identity(&self) -> &WordPressComponentIdentity {
        &self.identity
    }

    #[must_use]
    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }

    #[must_use]
    pub const fn source(&self) -> WordPressEvidenceSource {
        self.source
    }

    #[must_use]
    pub const fn confidence(&self) -> WordPressEvidenceConfidence {
        confidence_for_source(self.source)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WordPressComponentEvidenceClass {
    ObservedHint,
    OperatorSupplied,
    Conflicting,
    Unknown,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct WordPressVersionEvidence {
    value: String,
    source: WordPressEvidenceSource,
}

impl WordPressVersionEvidence {
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }

    #[must_use]
    pub const fn source(&self) -> WordPressEvidenceSource {
        self.source
    }

    #[must_use]
    pub const fn confidence(&self) -> WordPressEvidenceConfidence {
        confidence_for_source(self.source)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WordPressComponentAssessment {
    identity: WordPressComponentIdentity,
    evidence_class: WordPressComponentEvidenceClass,
    identity_sources: Vec<WordPressEvidenceSource>,
    confidence_classes: Vec<WordPressEvidenceConfidence>,
    versions: Vec<WordPressVersionEvidence>,
    activation: Option<WordPressActivationState>,
    inventory_status: Option<WordPressInventoryEntryStatus>,
}

impl WordPressComponentAssessment {
    #[must_use]
    pub const fn identity(&self) -> &WordPressComponentIdentity {
        &self.identity
    }

    #[must_use]
    pub const fn evidence_class(&self) -> WordPressComponentEvidenceClass {
        self.evidence_class
    }

    #[must_use]
    pub fn identity_sources(&self) -> &[WordPressEvidenceSource] {
        &self.identity_sources
    }

    #[must_use]
    pub fn confidence_classes(&self) -> &[WordPressEvidenceConfidence] {
        &self.confidence_classes
    }

    #[must_use]
    pub fn versions(&self) -> &[WordPressVersionEvidence] {
        &self.versions
    }

    #[must_use]
    pub const fn activation(&self) -> Option<WordPressActivationState> {
        self.activation
    }

    #[must_use]
    pub const fn inventory_status(&self) -> Option<WordPressInventoryEntryStatus> {
        self.inventory_status
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WordPressCatalogStatus {
    CatalogNotSupplied,
    Evaluated,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WordPressVersionRelation {
    WithinDeclaredRange,
    OutsideDeclaredRanges,
    Unknown,
    Unsupported,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WordPressVersionResolution {
    Missing,
    SupportedEquivalent,
    Conflicting,
    Unsupported,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WordPressVersionResolutionReason {
    NoVersionEvidence,
    SingleSupportedVersion,
    EquivalentSupportedVersions,
    ConflictingVersionEvidence,
    UnsupportedVersionEvidence,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WordPressPrerequisiteOutcome {
    MatchedOnSuppliedFacts,
    ContradictedOnSuppliedFacts,
    Unknown,
    Unsupported,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WordPressPrerequisiteEvaluation {
    prerequisite: WordPressPrerequisite,
    outcome: WordPressPrerequisiteOutcome,
}

impl WordPressPrerequisiteEvaluation {
    #[must_use]
    pub const fn prerequisite(&self) -> &WordPressPrerequisite {
        &self.prerequisite
    }

    #[must_use]
    pub const fn outcome(&self) -> WordPressPrerequisiteOutcome {
        self.outcome
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WordPressApplicability {
    CandidateMatchOnDeclaredFacts,
    ContradictedByDeclaredFacts,
    IndeterminateMissingEvidence,
    IndeterminateUnsupported,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WordPressExecutionStatus {
    NotPerformed,
}

/// The closed normalization policy for a local external advisory export.
///
/// Wordfence V3 documents structured bounds, but does not normatively define
/// version comparison. V1 therefore retains those bounds without choosing
/// either Termivar's numeric or PHP-subset comparator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WordPressExternalComparisonPolicy {
    WordfenceV3SourceSemanticsUnresolvedV1,
}

impl WordPressExternalComparisonPolicy {
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::WordfenceV3SourceSemanticsUnresolvedV1 => {
                "wordfence-v3/source-semantics-unresolved/v1"
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WordPressExternalVersionRelation {
    SourceComparisonSemanticsUnresolved,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WordPressExternalApplicability {
    IndeterminateUnsupported,
}

/// Comparator-neutral summary of the version declarations retained for one
/// externally evaluated component.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WordPressExternalVersionEvidenceStatus {
    Missing,
    SingleDeclaration,
    RepeatedExactDeclaration,
    MultipleDistinctDeclarations,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WordPressExternalVersionEvidenceResolution {
    status: WordPressExternalVersionEvidenceStatus,
    evidence_row_count: usize,
    distinct_spelling_count: usize,
}

impl WordPressExternalVersionEvidenceResolution {
    #[must_use]
    pub const fn status(&self) -> WordPressExternalVersionEvidenceStatus {
        self.status
    }

    #[must_use]
    pub const fn evidence_row_count(&self) -> usize {
        self.evidence_row_count
    }

    #[must_use]
    pub const fn distinct_spelling_count(&self) -> usize {
        self.distinct_spelling_count
    }
}

/// Stable identity of one upstream advisory/software association.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct WordPressExternalAssociationKey {
    source_namespace: String,
    upstream_id: String,
    component: WordPressComponentIdentity,
}

impl WordPressExternalAssociationKey {
    #[must_use]
    pub fn source_namespace(&self) -> &str {
        &self.source_namespace
    }

    #[must_use]
    pub fn upstream_id(&self) -> &str {
        &self.upstream_id
    }

    #[must_use]
    pub const fn component(&self) -> &WordPressComponentIdentity {
        &self.component
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WordPressExternalReviewCounts {
    parsed_records: usize,
    software_associations: usize,
    selected_associations: usize,
    evaluable_associations: usize,
    unsupported_associations: usize,
    excluded_associations: usize,
}

impl WordPressExternalReviewCounts {
    #[must_use]
    pub const fn parsed_records(&self) -> usize {
        self.parsed_records
    }

    #[must_use]
    pub const fn software_associations(&self) -> usize {
        self.software_associations
    }

    #[must_use]
    pub const fn selected_associations(&self) -> usize {
        self.selected_associations
    }

    #[must_use]
    pub const fn evaluable_associations(&self) -> usize {
        self.evaluable_associations
    }

    #[must_use]
    pub const fn unsupported_associations(&self) -> usize {
        self.unsupported_associations
    }

    #[must_use]
    pub const fn excluded_associations(&self) -> usize {
        self.excluded_associations
    }
}

/// One selected external advisory/software association. Provider-declared
/// fields are retained as inert metadata and are not converted into native
/// Termivar advisory authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WordPressExternalAdvisoryEvaluation {
    key: WordPressExternalAssociationKey,
    title: String,
    informational: bool,
    description: String,
    references: Vec<String>,
    cwe: Option<WordfenceV3Cwe>,
    cvss: Option<WordfenceV3Cvss>,
    cve: Option<String>,
    cve_link: Option<String>,
    researchers: Vec<String>,
    published: Option<String>,
    updated: Option<String>,
    notice_ids: Vec<String>,
    display_name: String,
    affected_ranges: Vec<WordfenceV3AffectedRange>,
    source_patched: bool,
    source_patched_versions: Vec<String>,
    source_remediation: String,
    component_evidence: WordPressComponentEvidenceClass,
    version_evidence_resolution: WordPressExternalVersionEvidenceResolution,
    comparison_policy: WordPressExternalComparisonPolicy,
    version_relation: WordPressExternalVersionRelation,
    applicability: WordPressExternalApplicability,
}

impl WordPressExternalAdvisoryEvaluation {
    #[must_use]
    pub const fn key(&self) -> &WordPressExternalAssociationKey {
        &self.key
    }
    #[must_use]
    pub fn title(&self) -> &str {
        &self.title
    }
    #[must_use]
    pub const fn informational(&self) -> bool {
        self.informational
    }
    #[must_use]
    pub fn description(&self) -> &str {
        &self.description
    }
    #[must_use]
    pub fn references(&self) -> &[String] {
        &self.references
    }
    #[must_use]
    pub const fn cwe(&self) -> Option<&WordfenceV3Cwe> {
        self.cwe.as_ref()
    }
    #[must_use]
    pub const fn cvss(&self) -> Option<&WordfenceV3Cvss> {
        self.cvss.as_ref()
    }
    #[must_use]
    pub fn cve(&self) -> Option<&str> {
        self.cve.as_deref()
    }
    #[must_use]
    pub fn cve_link(&self) -> Option<&str> {
        self.cve_link.as_deref()
    }
    #[must_use]
    pub fn researchers(&self) -> &[String] {
        &self.researchers
    }
    #[must_use]
    pub fn published(&self) -> Option<&str> {
        self.published.as_deref()
    }
    #[must_use]
    pub fn updated(&self) -> Option<&str> {
        self.updated.as_deref()
    }
    #[must_use]
    pub fn notice_ids(&self) -> &[String] {
        &self.notice_ids
    }
    #[must_use]
    pub fn display_name(&self) -> &str {
        &self.display_name
    }
    #[must_use]
    pub fn affected_ranges(&self) -> &[WordfenceV3AffectedRange] {
        &self.affected_ranges
    }
    #[must_use]
    pub const fn source_patched(&self) -> bool {
        self.source_patched
    }
    #[must_use]
    pub fn source_patched_versions(&self) -> &[String] {
        &self.source_patched_versions
    }
    #[must_use]
    pub fn source_remediation(&self) -> &str {
        &self.source_remediation
    }
    #[must_use]
    pub const fn component_evidence(&self) -> WordPressComponentEvidenceClass {
        self.component_evidence
    }
    #[must_use]
    pub const fn version_evidence_resolution(&self) -> &WordPressExternalVersionEvidenceResolution {
        &self.version_evidence_resolution
    }
    #[must_use]
    pub const fn comparison_policy(&self) -> WordPressExternalComparisonPolicy {
        self.comparison_policy
    }
    #[must_use]
    pub const fn version_relation(&self) -> WordPressExternalVersionRelation {
        self.version_relation
    }
    #[must_use]
    pub const fn applicability(&self) -> WordPressExternalApplicability {
        self.applicability
    }
    #[must_use]
    pub const fn exploit_execution(&self) -> WordPressExecutionStatus {
        WordPressExecutionStatus::NotPerformed
    }
    #[must_use]
    pub const fn impact_validation(&self) -> WordPressExecutionStatus {
        WordPressExecutionStatus::NotPerformed
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WordPressExternalReview {
    byte_length: u64,
    sha256: [u8; 32],
    semantic_sha256: [u8; 32],
    retained_bytes: usize,
    counts: WordPressExternalReviewCounts,
    notices: Vec<WordfenceV3Notice>,
    evaluations: Vec<WordPressExternalAdvisoryEvaluation>,
}

impl WordPressExternalReview {
    #[must_use]
    pub const fn source_namespace(&self) -> &'static str {
        WORDFENCE_V3_SOURCE_NAMESPACE
    }
    #[must_use]
    pub const fn source_format(&self) -> &'static str {
        WORDFENCE_V3_PRODUCTION_FORMAT
    }
    #[must_use]
    pub const fn mapping_revision(&self) -> &'static str {
        WORDFENCE_V3_MAPPING_REVISION
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
    pub const fn semantic_sha256(&self) -> &[u8; 32] {
        &self.semantic_sha256
    }
    #[must_use]
    pub const fn retained_bytes(&self) -> usize {
        self.retained_bytes
    }
    #[must_use]
    pub const fn counts(&self) -> &WordPressExternalReviewCounts {
        &self.counts
    }
    #[must_use]
    pub fn notices(&self) -> &[WordfenceV3Notice] {
        &self.notices
    }
    #[must_use]
    pub fn evaluations(&self) -> &[WordPressExternalAdvisoryEvaluation] {
        &self.evaluations
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WordPressAdvisoryEvaluation {
    record: WordPressAdvisoryRecord,
    component_evidence: WordPressComponentEvidenceClass,
    version_relation: WordPressVersionRelation,
    version_resolution: Option<WordPressVersionResolution>,
    version_resolution_reason: Option<WordPressVersionResolutionReason>,
    prerequisites: Vec<WordPressPrerequisiteEvaluation>,
    applicability: WordPressApplicability,
}

impl WordPressAdvisoryEvaluation {
    #[must_use]
    pub const fn record(&self) -> &WordPressAdvisoryRecord {
        &self.record
    }

    #[must_use]
    pub const fn component_evidence(&self) -> WordPressComponentEvidenceClass {
        self.component_evidence
    }

    #[must_use]
    pub const fn version_relation(&self) -> WordPressVersionRelation {
        self.version_relation
    }

    #[must_use]
    pub const fn version_resolution(&self) -> Option<WordPressVersionResolution> {
        self.version_resolution
    }

    #[must_use]
    pub const fn version_resolution_reason(&self) -> Option<WordPressVersionResolutionReason> {
        self.version_resolution_reason
    }

    #[must_use]
    pub fn prerequisites(&self) -> &[WordPressPrerequisiteEvaluation] {
        &self.prerequisites
    }

    #[must_use]
    pub const fn applicability(&self) -> WordPressApplicability {
        self.applicability
    }

    #[must_use]
    pub const fn exploit_execution(&self) -> WordPressExecutionStatus {
        WordPressExecutionStatus::NotPerformed
    }

    #[must_use]
    pub const fn impact_validation(&self) -> WordPressExecutionStatus {
        WordPressExecutionStatus::NotPerformed
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WordPressReviewResult {
    catalog_status: WordPressCatalogStatus,
    catalog_schema: Option<WordPressAdvisoryCatalogSchema>,
    catalog_metadata: Option<WordPressCatalogMetadata>,
    components: Vec<WordPressComponentAssessment>,
    advisories: Vec<WordPressAdvisoryEvaluation>,
    external_review: Option<WordPressExternalReview>,
    inventory_summary: Option<WordPressSavedInventorySummary>,
    local_input_provenance: Vec<WordPressLocalInputProvenance>,
}

impl WordPressReviewResult {
    #[must_use]
    pub const fn catalog_status(&self) -> WordPressCatalogStatus {
        self.catalog_status
    }

    #[must_use]
    pub const fn catalog_schema(&self) -> Option<WordPressAdvisoryCatalogSchema> {
        self.catalog_schema
    }

    #[must_use]
    pub const fn catalog_metadata(&self) -> Option<&WordPressCatalogMetadata> {
        self.catalog_metadata.as_ref()
    }

    #[must_use]
    pub fn components(&self) -> &[WordPressComponentAssessment] {
        &self.components
    }

    #[must_use]
    pub fn advisories(&self) -> &[WordPressAdvisoryEvaluation] {
        &self.advisories
    }

    #[must_use]
    pub const fn external_review(&self) -> Option<&WordPressExternalReview> {
        self.external_review.as_ref()
    }

    #[must_use]
    pub const fn inventory_summary(&self) -> Option<&WordPressSavedInventorySummary> {
        self.inventory_summary.as_ref()
    }

    #[must_use]
    pub fn local_input_provenance(&self) -> &[WordPressLocalInputProvenance] {
        &self.local_input_provenance
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum WordPressReviewError {
    #[error("WordPress context exceeds its byte limit")]
    ContextTooLarge,
    #[error("WordPress advisory catalog exceeds its byte limit")]
    CatalogTooLarge,
    #[error("saved WordPress inventory exceeds its aggregate byte limit")]
    InventoryTooLarge,
    #[error("WordPress input is empty")]
    EmptyInput,
    #[error("WordPress input contains a duplicate object key")]
    DuplicateKey,
    #[error("WordPress input exceeds a structural limit")]
    JsonLimitExceeded,
    #[error("WordPress input is not valid bounded JSON")]
    MalformedJson,
    #[error("WordPress input uses an unsupported schema")]
    UnsupportedSchema,
    #[error("WordPress context is invalid")]
    InvalidContext,
    #[error("saved WordPress inventory is invalid")]
    InvalidInventory,
    #[error("saved WordPress inventory exceeds its component limit")]
    InventoryComponentLimitExceeded,
    #[error("saved WordPress inventory provenance does not match its supplied inputs")]
    InvalidInventoryProvenance,
    #[error("WordPress advisory catalog is invalid")]
    InvalidCatalog,
    #[error("native and external WordPress advisory inputs cannot be combined")]
    ConflictingAdvisoryInputs,
    #[error("external WordPress advisory data cannot be represented within review limits")]
    InvalidExternalCatalog,
    #[error("WordPress component identity is invalid")]
    InvalidComponentIdentity,
    #[error("WordPress input repeats a component identity")]
    DuplicateComponent,
    #[error("WordPress advisory catalog repeats a record identity")]
    DuplicateAdvisory,
    #[error("WordPress advisory contains an invalid affected range")]
    InvalidVersionRange,
    #[error("WordPress response signal limit exceeded")]
    SignalLimitExceeded,
    #[error("WordPress review result limit exceeded")]
    ResultLimitExceeded,
    #[error("WordPress advisory evaluation work limit exceeded")]
    EvaluationLimitExceeded,
}

pub fn parse_wordpress_context(bytes: &[u8]) -> Result<WordPressContext, WordPressReviewError> {
    let value = parse_bounded_json(
        bytes,
        MAX_WORDPRESS_CONTEXT_BYTES,
        MAX_CONTEXT_JSON_NODES,
        MAX_WORDPRESS_CONTEXT_COMPONENTS,
        WordPressReviewError::ContextTooLarge,
    )?;
    require_schema(&value, WORDPRESS_CONTEXT_SCHEMA)?;
    let wire: ContextWire =
        serde_json::from_value(value).map_err(|_| WordPressReviewError::InvalidContext)?;
    let root_url = validate_root_url(&wire.root)?;
    if wire.components.len() > MAX_WORDPRESS_CONTEXT_COMPONENTS {
        return Err(WordPressReviewError::InvalidContext);
    }
    let mut identities = BTreeSet::new();
    let mut components = Vec::with_capacity(wire.components.len());
    for component in wire.components {
        let identity = WordPressComponentIdentity::new(component.kind.into(), component.slug)?;
        if !identities.insert(identity.clone()) {
            return Err(WordPressReviewError::DuplicateComponent);
        }
        let version = component
            .version
            .as_deref()
            .map(validate_source_version)
            .transpose()?;
        let patches = validate_patches(component.patches)?;
        components.push(WordPressContextComponent {
            identity,
            version,
            activation: component.activation.map(Into::into),
            patches,
            inventory_status: None,
        });
    }
    components.sort_by(|left, right| left.identity.cmp(&right.identity));
    Ok(WordPressContext {
        root_url,
        hosting_os: wire.hosting_os.map(Into::into),
        multisite: wire.multisite.map(Into::into),
        components,
    })
}

pub fn parse_wordpress_advisory_catalog(
    bytes: &[u8],
) -> Result<WordPressAdvisoryCatalog, WordPressReviewError> {
    let value = parse_bounded_json(
        bytes,
        MAX_WORDPRESS_ADVISORY_CATALOG_BYTES,
        MAX_CATALOG_JSON_NODES,
        MAX_WORDPRESS_ADVISORY_RECORDS,
        WordPressReviewError::CatalogTooLarge,
    )?;
    let schema = match value.get("schema").and_then(Value::as_str) {
        Some(WORDPRESS_ADVISORY_CATALOG_SCHEMA) => WordPressAdvisoryCatalogSchema::V1,
        Some(WORDPRESS_ADVISORY_CATALOG_SCHEMA_V2) => WordPressAdvisoryCatalogSchema::V2,
        _ => return Err(WordPressReviewError::UnsupportedSchema),
    };
    let (catalog, records) = match schema {
        WordPressAdvisoryCatalogSchema::V1 => {
            let wire: CatalogV1Wire =
                serde_json::from_value(value).map_err(|_| WordPressReviewError::InvalidCatalog)?;
            (
                wire.catalog,
                wire.records
                    .into_iter()
                    .map(AdvisoryRecordInput::from)
                    .collect::<Vec<_>>(),
            )
        },
        WordPressAdvisoryCatalogSchema::V2 => {
            let wire: CatalogV2Wire =
                serde_json::from_value(value).map_err(|_| WordPressReviewError::InvalidCatalog)?;
            (
                wire.catalog,
                wire.records
                    .into_iter()
                    .map(AdvisoryRecordInput::try_from)
                    .collect::<Result<Vec<_>, _>>()?,
            )
        },
    };
    validate_identifier(&catalog.id)?;
    validate_identifier(&catalog.revision)?;
    validate_date(&catalog.retrieved_on)?;
    if records.len() > MAX_WORDPRESS_ADVISORY_RECORDS {
        return Err(WordPressReviewError::InvalidCatalog);
    }
    let metadata = WordPressCatalogMetadata {
        id: catalog.id,
        revision: catalog.revision,
        retrieved_on: catalog.retrieved_on,
    };
    let mut record_ids = BTreeSet::new();
    let mut validated_records = Vec::with_capacity(records.len());
    let mut work = 0_usize;
    for record in records {
        validate_identifier(&record.id)?;
        if !record_ids.insert(record.id.clone()) {
            return Err(WordPressReviewError::DuplicateAdvisory);
        }
        let component =
            WordPressComponentIdentity::new(record.component.kind.into(), record.component.slug)?;
        let source = validate_source(record.source)?;
        if let Some(cve) = record.cve.as_deref() {
            if !valid_cve(cve) {
                return Err(WordPressReviewError::InvalidCatalog);
            }
        }
        validate_text(&record.summary, MAX_WORDPRESS_SUMMARY_BYTES)?;
        if record.affected_ranges.len() > MAX_WORDPRESS_RANGES_PER_ADVISORY
            || record.fixed_versions.len() > MAX_WORDPRESS_FIXED_VERSIONS_PER_ADVISORY
            || record.prerequisites.len() > MAX_WORDPRESS_PREREQUISITES_PER_ADVISORY
        {
            return Err(WordPressReviewError::InvalidCatalog);
        }
        work = work
            .checked_add(record.affected_ranges.len())
            .and_then(|value| value.checked_add(record.prerequisites.len()))
            .ok_or(WordPressReviewError::EvaluationLimitExceeded)?;
        if work > MAX_WORDPRESS_EVALUATION_WORK {
            return Err(WordPressReviewError::EvaluationLimitExceeded);
        }
        let (affected_ranges, profiled_affected_ranges) = match schema {
            WordPressAdvisoryCatalogSchema::V1 => {
                let mut ranges = record
                    .affected_ranges
                    .into_iter()
                    .map(validate_range)
                    .collect::<Result<Vec<_>, _>>()?;
                ranges.sort();
                ranges.dedup();
                (ranges, Vec::new())
            },
            WordPressAdvisoryCatalogSchema::V2 => {
                let mut ranges = record
                    .affected_ranges
                    .into_iter()
                    .map(|range| validate_profiled_range(range, record.comparison_profile))
                    .collect::<Result<Vec<_>, _>>()?;
                ranges.sort_by(compare_profiled_ranges);
                ranges.dedup_by(|left, right| profiled_ranges_equivalent(left, right));
                (Vec::new(), ranges)
            },
        };
        let mut fixed_versions: Vec<(ProfiledVersionKey, String)> =
            Vec::with_capacity(record.fixed_versions.len());
        for fixed in record.fixed_versions {
            let parsed = ProfiledVersionKey::parse(record.comparison_profile, &fixed)
                .map_err(|_| WordPressReviewError::InvalidVersionRange)?;
            if fixed_versions
                .iter()
                .any(|(existing, _)| existing.compare(&parsed).ok() == Some(Ordering::Equal))
            {
                return Err(WordPressReviewError::InvalidCatalog);
            }
            fixed_versions.push((parsed, fixed));
        }
        fixed_versions.sort_by(|left, right| {
            left.0
                .compare(&right.0)
                .expect("one record has exactly one validated comparison profile")
                .then_with(|| left.1.cmp(&right.1))
        });
        let fixed_versions = fixed_versions
            .into_iter()
            .map(|(_, declared)| declared)
            .collect();
        let mut prerequisites = record
            .prerequisites
            .into_iter()
            .map(validate_prerequisite)
            .collect::<Result<Vec<_>, _>>()?;
        prerequisites.sort();
        if prerequisites.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(WordPressReviewError::InvalidCatalog);
        }
        let remediation = record
            .remediation
            .map(|value| {
                validate_text(&value, MAX_WORDPRESS_REMEDIATION_BYTES)?;
                Ok(value)
            })
            .transpose()?;
        validated_records.push(WordPressAdvisoryRecord {
            id: record.id,
            component,
            source,
            cve: record.cve,
            summary: record.summary,
            affected_ranges,
            profiled_affected_ranges,
            comparison_profile: record.comparison_profile,
            fixed_versions,
            prerequisites,
            remediation,
        });
    }
    validated_records.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(WordPressAdvisoryCatalog {
        schema,
        metadata,
        records: validated_records,
    })
}

pub fn evaluate_wordpress_review(
    signals: &[WordPressComponentSignal],
    inputs: &WordPressReviewInputs,
) -> Result<WordPressReviewResult, WordPressReviewError> {
    if signals.len() > MAX_WORDPRESS_SIGNALS {
        return Err(WordPressReviewError::SignalLimitExceeded);
    }
    let mut aggregates = BTreeMap::<WordPressComponentIdentity, ComponentAggregate>::new();
    for signal in signals {
        let aggregate = aggregates.entry(signal.identity.clone()).or_default();
        aggregate.sources.insert(signal.source);
        aggregate.confidence_classes.insert(signal.confidence());
        if let Some(version) = &signal.version {
            aggregate.versions.insert(WordPressVersionEvidence {
                value: version.clone(),
                source: signal.source,
            });
        }
    }
    if let Some(context) = inputs.context() {
        for component in context.components() {
            let aggregate = aggregates.entry(component.identity.clone()).or_default();
            aggregate
                .sources
                .insert(WordPressEvidenceSource::OperatorContext);
            aggregate
                .confidence_classes
                .insert(WordPressEvidenceConfidence::OperatorAssertion);
            aggregate.activation = component.activation;
            aggregate.inventory_status = component.inventory_status;
            if let Some(version) = &component.version {
                aggregate.versions.insert(WordPressVersionEvidence {
                    value: version.clone(),
                    source: WordPressEvidenceSource::OperatorContext,
                });
            }
        }
    }
    let result_version_count = aggregates.values().try_fold(0_usize, |count, aggregate| {
        count.checked_add(aggregate.versions.len())
    });
    if aggregates.len() > MAX_WORDPRESS_RESULT_COMPONENTS
        || result_version_count.is_none_or(|count| count > MAX_WORDPRESS_RESULT_VERSION_EVIDENCE)
    {
        return Err(WordPressReviewError::ResultLimitExceeded);
    }
    let mut components = Vec::with_capacity(aggregates.len());
    let profiled_catalog = inputs
        .catalog()
        .is_some_and(|catalog| catalog.schema() == WordPressAdvisoryCatalogSchema::V2)
        || inputs.wordfence_v3_catalog().is_some();
    for (identity, aggregate) in &aggregates {
        components.push(component_assessment(
            identity.clone(),
            aggregate,
            profiled_catalog,
        ));
    }
    if let Some(catalog) = inputs.wordfence_v3_catalog() {
        let external_review = evaluate_wordfence_v3_review(catalog, &components)?;
        return Ok(WordPressReviewResult {
            catalog_status: WordPressCatalogStatus::Evaluated,
            catalog_schema: None,
            catalog_metadata: None,
            components,
            advisories: Vec::new(),
            external_review: Some(external_review),
            inventory_summary: inputs.inventory_summary.clone(),
            local_input_provenance: inputs.local_input_provenance.clone(),
        });
    }
    let Some(catalog) = inputs.catalog() else {
        return Ok(WordPressReviewResult {
            catalog_status: WordPressCatalogStatus::CatalogNotSupplied,
            catalog_schema: None,
            catalog_metadata: None,
            components,
            advisories: Vec::new(),
            external_review: None,
            inventory_summary: inputs.inventory_summary.clone(),
            local_input_provenance: inputs.local_input_provenance.clone(),
        });
    };
    let work = catalog.records().iter().try_fold(0_usize, |work, record| {
        work.checked_add(record.affected_range_count())?
            .checked_add(record.prerequisites.len())
    });
    if work.is_none_or(|work| work > MAX_WORDPRESS_EVALUATION_WORK) {
        return Err(WordPressReviewError::EvaluationLimitExceeded);
    }
    let assessments = components
        .iter()
        .map(|assessment| (assessment.identity.clone(), assessment))
        .collect::<BTreeMap<_, _>>();
    let mut profiled_resolutions = BTreeMap::new();
    if catalog.schema() == WordPressAdvisoryCatalogSchema::V2 {
        let profiles = catalog
            .records()
            .iter()
            .map(WordPressAdvisoryRecord::comparison_profile)
            .collect::<BTreeSet<_>>();
        let mut resolution_work = 0_usize;
        for (identity, assessment) in &assessments {
            for profile in &profiles {
                resolution_work = resolution_work
                    .checked_add(assessment.versions().len())
                    .ok_or(WordPressReviewError::EvaluationLimitExceeded)?;
                if resolution_work > MAX_WORDPRESS_VERSION_RESOLUTION_WORK {
                    return Err(WordPressReviewError::EvaluationLimitExceeded);
                }
                profiled_resolutions.insert(
                    ((*identity).clone(), *profile),
                    resolve_profiled_versions(assessment, *profile),
                );
            }
        }
    }
    let mut advisories = Vec::with_capacity(catalog.records().len());
    for record in catalog.records() {
        let assessment = assessments.get(record.component());
        let (component_evidence, version_relation, version_resolution, resolution_reason) =
            match catalog.schema() {
                WordPressAdvisoryCatalogSchema::V1 => {
                    let component_evidence = assessment
                        .map_or(WordPressComponentEvidenceClass::Unknown, |assessment| {
                            assessment.evidence_class
                        });
                    (
                        component_evidence,
                        evaluate_version_relation(assessment.copied(), record),
                        None,
                        None,
                    )
                },
                WordPressAdvisoryCatalogSchema::V2 => {
                    let resolution = assessment
                        .and_then(|assessment| {
                            profiled_resolutions
                                .get(&(assessment.identity().clone(), record.comparison_profile()))
                        })
                        .cloned()
                        .unwrap_or_else(VersionResolutionState::missing);
                    (
                        assessment.map_or(WordPressComponentEvidenceClass::Unknown, |assessment| {
                            profile_independent_component_evidence(assessment)
                        }),
                        evaluate_profiled_version_relation(&resolution, record),
                        Some(resolution.status),
                        Some(resolution.reason),
                    )
                },
            };
        let prerequisites = record
            .prerequisites
            .iter()
            .cloned()
            .map(|prerequisite| {
                let outcome =
                    evaluate_prerequisite(&prerequisite, inputs.context(), record.component());
                WordPressPrerequisiteEvaluation {
                    prerequisite,
                    outcome,
                }
            })
            .collect::<Vec<_>>();
        let applicability =
            summarize_applicability(component_evidence, version_relation, &prerequisites);
        advisories.push(WordPressAdvisoryEvaluation {
            record: record.clone(),
            component_evidence,
            version_relation,
            version_resolution,
            version_resolution_reason: resolution_reason,
            prerequisites,
            applicability,
        });
    }
    Ok(WordPressReviewResult {
        catalog_status: WordPressCatalogStatus::Evaluated,
        catalog_schema: Some(catalog.schema()),
        catalog_metadata: Some(catalog.metadata().clone()),
        components,
        advisories,
        external_review: None,
        inventory_summary: inputs.inventory_summary.clone(),
        local_input_provenance: inputs.local_input_provenance.clone(),
    })
}

fn evaluate_wordfence_v3_review(
    catalog: &WordfenceV3Catalog,
    components: &[WordPressComponentAssessment],
) -> Result<WordPressExternalReview, WordPressReviewError> {
    let assessments = components
        .iter()
        .map(|assessment| (assessment.identity().clone(), assessment))
        .collect::<BTreeMap<_, _>>();
    let mut selected = Vec::new();
    let mut keys = BTreeSet::new();
    let mut selected_notice_ids = BTreeSet::new();
    let mut evaluation_work = 0_usize;
    let mut projected_result_bytes = 0_usize;
    for (component, assessment) in &assessments {
        for view in catalog.associations_for(component) {
            if selected.len() == MAX_WORDPRESS_ADVISORY_RECORDS {
                return Err(WordPressReviewError::ResultLimitExceeded);
            }
            let record = view.record();
            let association = view.association();
            projected_result_bytes = projected_result_bytes
                .checked_add(wordfence_v3_projection_bytes(record, association)?)
                .ok_or(WordPressReviewError::ResultLimitExceeded)?;
            if projected_result_bytes > MAX_WORDPRESS_EXTERNAL_RESULT_BYTES {
                return Err(WordPressReviewError::ResultLimitExceeded);
            }
            evaluation_work = evaluation_work
                .checked_add(association.affected_ranges().len())
                .ok_or(WordPressReviewError::EvaluationLimitExceeded)?;
            if evaluation_work > MAX_WORDPRESS_EVALUATION_WORK {
                return Err(WordPressReviewError::EvaluationLimitExceeded);
            }
            let key = WordPressExternalAssociationKey {
                source_namespace: WORDFENCE_V3_SOURCE_NAMESPACE.to_owned(),
                upstream_id: record.upstream_id().to_owned(),
                component: association.component().clone(),
            };
            if !keys.insert(key.clone()) {
                return Err(WordPressReviewError::InvalidExternalCatalog);
            }
            selected_notice_ids.extend(record.notice_ids().iter().cloned());
            if selected_notice_ids.len() > MAX_WORDPRESS_ADVISORY_RECORDS {
                return Err(WordPressReviewError::ResultLimitExceeded);
            }
            selected.push(WordPressExternalAdvisoryEvaluation {
                key,
                title: record.title().to_owned(),
                informational: record.informational(),
                description: record.description().to_owned(),
                references: record.references().to_vec(),
                cwe: record.cwe().cloned(),
                cvss: record.cvss().cloned(),
                cve: record.cve().map(str::to_owned),
                cve_link: record.cve_link().map(str::to_owned),
                researchers: record.researchers().to_vec(),
                published: record.published().map(str::to_owned),
                updated: record.updated().map(str::to_owned),
                notice_ids: record.notice_ids().to_vec(),
                display_name: association.display_name().to_owned(),
                affected_ranges: association.affected_ranges().to_vec(),
                source_patched: association.patched(),
                source_patched_versions: association.patched_versions().to_vec(),
                source_remediation: association.remediation().to_owned(),
                component_evidence: profile_independent_component_evidence(assessment),
                version_evidence_resolution: external_version_evidence_resolution(assessment)?,
                comparison_policy:
                    WordPressExternalComparisonPolicy::WordfenceV3SourceSemanticsUnresolvedV1,
                version_relation:
                    WordPressExternalVersionRelation::SourceComparisonSemanticsUnresolved,
                applicability: WordPressExternalApplicability::IndeterminateUnsupported,
            });
        }
    }
    selected.sort_by(|left, right| left.key.cmp(&right.key));

    let notices_by_id = catalog
        .notices()
        .iter()
        .map(|notice| (notice.id(), notice))
        .collect::<BTreeMap<_, _>>();
    let mut notices = Vec::with_capacity(selected_notice_ids.len());
    for id in &selected_notice_ids {
        let notice = notices_by_id
            .get(id.as_str())
            .copied()
            .ok_or(WordPressReviewError::InvalidExternalCatalog)?;
        projected_result_bytes = projected_result_bytes
            .checked_add(wordfence_v3_notice_projection_bytes(notice)?)
            .ok_or(WordPressReviewError::ResultLimitExceeded)?;
        if projected_result_bytes > MAX_WORDPRESS_EXTERNAL_RESULT_BYTES {
            return Err(WordPressReviewError::ResultLimitExceeded);
        }
        notices.push(notice.clone());
    }
    let selected_associations = selected.len();
    let software_associations = catalog.software_association_count();
    let excluded_associations = software_associations
        .checked_sub(selected_associations)
        .ok_or(WordPressReviewError::InvalidExternalCatalog)?;
    Ok(WordPressExternalReview {
        byte_length: catalog.byte_length(),
        sha256: *catalog.sha256(),
        semantic_sha256: *catalog.semantic_sha256(),
        retained_bytes: catalog.retained_bytes(),
        counts: WordPressExternalReviewCounts {
            parsed_records: catalog.record_count(),
            software_associations,
            selected_associations,
            evaluable_associations: 0,
            unsupported_associations: selected_associations,
            excluded_associations,
        },
        notices,
        evaluations: selected,
    })
}

fn external_version_evidence_resolution(
    assessment: &WordPressComponentAssessment,
) -> Result<WordPressExternalVersionEvidenceResolution, WordPressReviewError> {
    let evidence_row_count = assessment.versions.len();
    let distinct_spelling_count = assessment
        .versions
        .iter()
        .map(|version| version.value.as_str())
        .collect::<BTreeSet<_>>()
        .len();
    let status = match (evidence_row_count, distinct_spelling_count) {
        (0, 0) => WordPressExternalVersionEvidenceStatus::Missing,
        (1, 1) => WordPressExternalVersionEvidenceStatus::SingleDeclaration,
        (count, 1) if count > 1 => WordPressExternalVersionEvidenceStatus::RepeatedExactDeclaration,
        (count, distinct) if count > 1 && distinct > 1 && distinct <= count => {
            WordPressExternalVersionEvidenceStatus::MultipleDistinctDeclarations
        },
        _ => return Err(WordPressReviewError::InvalidExternalCatalog),
    };
    Ok(WordPressExternalVersionEvidenceResolution {
        status,
        evidence_row_count,
        distinct_spelling_count,
    })
}

fn wordfence_v3_projection_bytes(
    record: &WordfenceV3Record,
    association: &WordfenceV3SoftwareAssociation,
) -> Result<usize, WordPressReviewError> {
    let mut total = 512_usize;
    for value in [
        record.upstream_id(),
        record.title(),
        record.description(),
        record.cve().unwrap_or_default(),
        record.cve_link().unwrap_or_default(),
        record.published().unwrap_or_default(),
        record.updated().unwrap_or_default(),
        association.display_name(),
        association.remediation(),
    ] {
        total = total
            .checked_add(value.len())
            .ok_or(WordPressReviewError::ResultLimitExceeded)?;
    }
    for value in record
        .references()
        .iter()
        .chain(record.researchers())
        .chain(record.notice_ids())
        .chain(association.patched_versions())
    {
        total = total
            .checked_add(value.len() + 16)
            .ok_or(WordPressReviewError::ResultLimitExceeded)?;
    }
    if let Some(cwe) = record.cwe() {
        total = total
            .checked_add(cwe.name().len() + cwe.description().len() + 32)
            .ok_or(WordPressReviewError::ResultLimitExceeded)?;
    }
    if let Some(cvss) = record.cvss() {
        total = total
            .checked_add(cvss.vector().len() + cvss.score().len() + 32)
            .ok_or(WordPressReviewError::ResultLimitExceeded)?;
    }
    for range in association.affected_ranges() {
        total = total
            .checked_add(
                range.label().len()
                    + range.from().value().declared().len()
                    + range.to().value().declared().len()
                    + 64,
            )
            .ok_or(WordPressReviewError::ResultLimitExceeded)?;
    }
    Ok(total)
}

fn wordfence_v3_notice_projection_bytes(
    notice: &WordfenceV3Notice,
) -> Result<usize, WordPressReviewError> {
    [
        notice.id(),
        notice.message(),
        notice.party(),
        notice.notice(),
        notice.license(),
        notice.license_url(),
    ]
    .iter()
    .try_fold(128_usize, |total, value| {
        total
            .checked_add(value.len())
            .ok_or(WordPressReviewError::ResultLimitExceeded)
    })
}

#[derive(Default)]
struct ComponentAggregate {
    sources: BTreeSet<WordPressEvidenceSource>,
    confidence_classes: BTreeSet<WordPressEvidenceConfidence>,
    versions: BTreeSet<WordPressVersionEvidence>,
    activation: Option<WordPressActivationState>,
    inventory_status: Option<WordPressInventoryEntryStatus>,
}

fn component_assessment(
    identity: WordPressComponentIdentity,
    aggregate: &ComponentAggregate,
    profiled_catalog: bool,
) -> WordPressComponentAssessment {
    let conflicting = !profiled_catalog && versions_conflict(&aggregate.versions);
    let observed = aggregate.sources.iter().any(|source| {
        matches!(
            source,
            WordPressEvidenceSource::GeneratorMetadata
                | WordPressEvidenceSource::SameOriginAssetPath
        )
    });
    let operator = aggregate
        .sources
        .contains(&WordPressEvidenceSource::OperatorContext);
    let evidence_class = if conflicting {
        WordPressComponentEvidenceClass::Conflicting
    } else if observed {
        WordPressComponentEvidenceClass::ObservedHint
    } else if operator {
        WordPressComponentEvidenceClass::OperatorSupplied
    } else {
        WordPressComponentEvidenceClass::Unknown
    };
    WordPressComponentAssessment {
        identity,
        evidence_class,
        identity_sources: aggregate.sources.iter().copied().collect(),
        confidence_classes: aggregate.confidence_classes.iter().copied().collect(),
        versions: aggregate.versions.iter().cloned().collect(),
        activation: aggregate.activation,
        inventory_status: aggregate.inventory_status,
    }
}

const fn confidence_for_source(source: WordPressEvidenceSource) -> WordPressEvidenceConfidence {
    match source {
        WordPressEvidenceSource::GeneratorMetadata => {
            WordPressEvidenceConfidence::PublicDeclaration
        },
        WordPressEvidenceSource::SameOriginAssetPath => WordPressEvidenceConfidence::StructuralHint,
        WordPressEvidenceSource::OperatorContext => WordPressEvidenceConfidence::OperatorAssertion,
    }
}

fn versions_conflict(versions: &BTreeSet<WordPressVersionEvidence>) -> bool {
    let mut normalized = BTreeSet::new();
    let mut unsupported = BTreeSet::new();
    for version in versions {
        match NumericDottedVersion::parse(&version.value) {
            Ok(version) => {
                normalized.insert(version);
            },
            Err(_) => {
                unsupported.insert(version.value.as_str());
            },
        }
    }
    normalized.len() > 1
        || unsupported.len() > 1
        || (!normalized.is_empty() && !unsupported.is_empty())
}

#[derive(Clone)]
struct VersionResolutionState {
    status: WordPressVersionResolution,
    reason: WordPressVersionResolutionReason,
    version: Option<ProfiledVersionKey>,
}

impl VersionResolutionState {
    fn missing() -> Self {
        Self {
            status: WordPressVersionResolution::Missing,
            reason: WordPressVersionResolutionReason::NoVersionEvidence,
            version: None,
        }
    }
}

fn resolve_profiled_versions(
    assessment: &WordPressComponentAssessment,
    profile: WordPressComparisonProfile,
) -> VersionResolutionState {
    if assessment.versions.is_empty() {
        return VersionResolutionState::missing();
    }
    let mut supported = None::<ProfiledVersionKey>;
    let mut supported_conflict = false;
    let mut unsupported = false;
    for evidence in &assessment.versions {
        match ProfiledVersionKey::parse(profile, &evidence.value) {
            Ok(version) => {
                if let Some(selected) = supported.as_ref() {
                    if selected.compare(&version).ok() != Some(Ordering::Equal) {
                        supported_conflict = true;
                    }
                } else {
                    supported = Some(version);
                }
            },
            Err(_) => {
                unsupported = true;
            },
        }
    }
    if supported_conflict {
        return VersionResolutionState {
            status: WordPressVersionResolution::Conflicting,
            reason: WordPressVersionResolutionReason::ConflictingVersionEvidence,
            version: None,
        };
    }
    if unsupported || supported.is_none() {
        return VersionResolutionState {
            status: WordPressVersionResolution::Unsupported,
            reason: WordPressVersionResolutionReason::UnsupportedVersionEvidence,
            version: None,
        };
    }
    VersionResolutionState {
        status: WordPressVersionResolution::SupportedEquivalent,
        reason: if assessment.versions.len() == 1 {
            WordPressVersionResolutionReason::SingleSupportedVersion
        } else {
            WordPressVersionResolutionReason::EquivalentSupportedVersions
        },
        version: supported,
    }
}

fn profile_independent_component_evidence(
    assessment: &WordPressComponentAssessment,
) -> WordPressComponentEvidenceClass {
    if assessment.identity_sources.iter().any(|source| {
        matches!(
            source,
            WordPressEvidenceSource::GeneratorMetadata
                | WordPressEvidenceSource::SameOriginAssetPath
        )
    }) {
        WordPressComponentEvidenceClass::ObservedHint
    } else if assessment
        .identity_sources
        .contains(&WordPressEvidenceSource::OperatorContext)
    {
        WordPressComponentEvidenceClass::OperatorSupplied
    } else {
        WordPressComponentEvidenceClass::Unknown
    }
}

fn evaluate_profiled_version_relation(
    resolution: &VersionResolutionState,
    record: &WordPressAdvisoryRecord,
) -> WordPressVersionRelation {
    match resolution.status {
        WordPressVersionResolution::Missing | WordPressVersionResolution::Conflicting => {
            WordPressVersionRelation::Unknown
        },
        WordPressVersionResolution::Unsupported => WordPressVersionRelation::Unsupported,
        WordPressVersionResolution::SupportedEquivalent => {
            let Some(version) = resolution.version.as_ref() else {
                return WordPressVersionRelation::Unsupported;
            };
            if record.profiled_affected_ranges.is_empty() {
                return WordPressVersionRelation::Unknown;
            }
            match record
                .profiled_affected_ranges
                .iter()
                .try_fold(false, |matched, range| {
                    range.contains(version).map(|contains| matched || contains)
                }) {
                Ok(true) => WordPressVersionRelation::WithinDeclaredRange,
                Ok(false) => WordPressVersionRelation::OutsideDeclaredRanges,
                Err(_) => WordPressVersionRelation::Unsupported,
            }
        },
    }
}

fn evaluate_version_relation(
    assessment: Option<&WordPressComponentAssessment>,
    record: &WordPressAdvisoryRecord,
) -> WordPressVersionRelation {
    let Some(assessment) = assessment else {
        return WordPressVersionRelation::Unknown;
    };
    if assessment.evidence_class == WordPressComponentEvidenceClass::Conflicting {
        return WordPressVersionRelation::Unknown;
    }
    let Some(version) = assessment.versions.first() else {
        return WordPressVersionRelation::Unknown;
    };
    let Ok(version) = NumericDottedVersion::parse(&version.value) else {
        return WordPressVersionRelation::Unsupported;
    };
    if record.affected_ranges.is_empty() {
        return WordPressVersionRelation::Unknown;
    }
    if record
        .affected_ranges
        .iter()
        .any(|range| range.contains(&version))
    {
        WordPressVersionRelation::WithinDeclaredRange
    } else {
        WordPressVersionRelation::OutsideDeclaredRanges
    }
}

fn evaluate_prerequisite(
    prerequisite: &WordPressPrerequisite,
    context: Option<&WordPressContext>,
    component: &WordPressComponentIdentity,
) -> WordPressPrerequisiteOutcome {
    let Some(context) = context else {
        return match prerequisite {
            WordPressPrerequisite::Unsupported { .. } => WordPressPrerequisiteOutcome::Unsupported,
            _ => WordPressPrerequisiteOutcome::Unknown,
        };
    };
    match prerequisite {
        WordPressPrerequisite::HostingOs { equals } => {
            compare_supplied(context.hosting_os, *equals)
        },
        WordPressPrerequisite::Multisite { equals } => compare_supplied(context.multisite, *equals),
        WordPressPrerequisite::Activation { equals } => {
            let supplied = context
                .components
                .iter()
                .find(|candidate| candidate.identity == *component)
                .and_then(|candidate| candidate.activation)
                .filter(|state| *state != WordPressActivationState::Unknown);
            compare_supplied(supplied, *equals)
        },
        WordPressPrerequisite::Patch { id, equals } => {
            let supplied = context
                .components
                .iter()
                .find(|candidate| candidate.identity == *component)
                .and_then(|candidate| candidate.patches.iter().find(|patch| patch.id == *id))
                .map(|patch| patch.state)
                .filter(|state| *state != WordPressPatchState::Unknown);
            compare_supplied(supplied, *equals)
        },
        WordPressPrerequisite::Unsupported { .. } => WordPressPrerequisiteOutcome::Unsupported,
    }
}

fn compare_supplied<T: Eq>(supplied: Option<T>, expected: T) -> WordPressPrerequisiteOutcome {
    match supplied {
        Some(value) if value == expected => WordPressPrerequisiteOutcome::MatchedOnSuppliedFacts,
        Some(_) => WordPressPrerequisiteOutcome::ContradictedOnSuppliedFacts,
        None => WordPressPrerequisiteOutcome::Unknown,
    }
}

fn summarize_applicability(
    component: WordPressComponentEvidenceClass,
    version: WordPressVersionRelation,
    prerequisites: &[WordPressPrerequisiteEvaluation],
) -> WordPressApplicability {
    if version == WordPressVersionRelation::OutsideDeclaredRanges
        || prerequisites.iter().any(|result| {
            result.outcome == WordPressPrerequisiteOutcome::ContradictedOnSuppliedFacts
        })
    {
        return WordPressApplicability::ContradictedByDeclaredFacts;
    }
    if version == WordPressVersionRelation::Unsupported
        || prerequisites
            .iter()
            .any(|result| result.outcome == WordPressPrerequisiteOutcome::Unsupported)
    {
        return WordPressApplicability::IndeterminateUnsupported;
    }
    if component == WordPressComponentEvidenceClass::Unknown
        || component == WordPressComponentEvidenceClass::Conflicting
        || version == WordPressVersionRelation::Unknown
        || prerequisites
            .iter()
            .any(|result| result.outcome == WordPressPrerequisiteOutcome::Unknown)
    {
        return WordPressApplicability::IndeterminateMissingEvidence;
    }
    WordPressApplicability::CandidateMatchOnDeclaredFacts
}

fn validate_patches(
    patches: Vec<PatchWire>,
) -> Result<Vec<WordPressPatchAssertion>, WordPressReviewError> {
    if patches.len() > MAX_WORDPRESS_PATCH_ASSERTIONS_PER_COMPONENT {
        return Err(WordPressReviewError::InvalidContext);
    }
    let mut seen = BTreeSet::new();
    let mut validated = Vec::with_capacity(patches.len());
    for patch in patches {
        if !valid_identifier(&patch.id) {
            return Err(WordPressReviewError::InvalidContext);
        }
        if !seen.insert(patch.id.clone()) {
            return Err(WordPressReviewError::InvalidContext);
        }
        validated.push(WordPressPatchAssertion {
            id: patch.id,
            state: patch.state.into(),
        });
    }
    validated.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(validated)
}

fn validate_source(source: SourceWire) -> Result<WordPressAdvisorySource, WordPressReviewError> {
    validate_identifier(&source.revision)?;
    validate_date(&source.retrieved_on)?;
    validate_text(&source.usage_basis, 256)?;
    if source.reference.len() > MAX_WORDPRESS_REFERENCE_BYTES {
        return Err(WordPressReviewError::InvalidCatalog);
    }
    let url = Url::parse(&source.reference).map_err(|_| WordPressReviewError::InvalidCatalog)?;
    if url.scheme() != "https"
        || !url.has_host()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(WordPressReviewError::InvalidCatalog);
    }
    Ok(WordPressAdvisorySource {
        reference: source.reference,
        revision: source.revision,
        retrieved_on: source.retrieved_on,
        usage_basis: source.usage_basis,
    })
}

fn validate_range(range: RangeWire) -> Result<WordPressAffectedRange, WordPressReviewError> {
    if range.lower.is_none() && range.upper.is_none() {
        return Err(WordPressReviewError::InvalidVersionRange);
    }
    let lower = range.lower.map(validate_endpoint).transpose()?;
    let upper = range.upper.map(validate_endpoint).transpose()?;
    if let (Some(lower), Some(upper)) = (&lower, &upper) {
        match lower.version.cmp(&upper.version) {
            Ordering::Greater => return Err(WordPressReviewError::InvalidVersionRange),
            Ordering::Equal if !(lower.inclusive && upper.inclusive) => {
                return Err(WordPressReviewError::InvalidVersionRange);
            },
            Ordering::Less | Ordering::Equal => {},
        }
    }
    Ok(WordPressAffectedRange { lower, upper })
}

fn validate_endpoint(
    endpoint: EndpointWire,
) -> Result<WordPressVersionEndpoint, WordPressReviewError> {
    let version = NumericDottedVersion::parse(&endpoint.version)
        .map_err(|_| WordPressReviewError::InvalidVersionRange)?;
    Ok(WordPressVersionEndpoint {
        declared: endpoint.version,
        version,
        inclusive: endpoint.inclusive,
    })
}

fn validate_prerequisite(
    prerequisite: PrerequisiteWire,
) -> Result<WordPressPrerequisite, WordPressReviewError> {
    Ok(match prerequisite {
        PrerequisiteWire::HostingOs { equals } => WordPressPrerequisite::HostingOs {
            equals: equals.into(),
        },
        PrerequisiteWire::Multisite { equals } => WordPressPrerequisite::Multisite {
            equals: equals.into(),
        },
        PrerequisiteWire::Activation { equals } => {
            let equals = equals.into();
            if equals == WordPressActivationState::Unknown {
                return Err(WordPressReviewError::InvalidCatalog);
            }
            WordPressPrerequisite::Activation { equals }
        },
        PrerequisiteWire::Patch { id, equals } => {
            validate_identifier(&id)?;
            let equals = equals.into();
            if equals == WordPressPatchState::Unknown {
                return Err(WordPressReviewError::InvalidCatalog);
            }
            WordPressPrerequisite::Patch { id, equals }
        },
        PrerequisiteWire::Unsupported { name } => {
            validate_identifier(&name)?;
            WordPressPrerequisite::Unsupported { name }
        },
    })
}

fn validate_root_url(value: &str) -> Result<Url, WordPressReviewError> {
    if value.len() > MAX_WORDPRESS_REFERENCE_BYTES {
        return Err(WordPressReviewError::InvalidContext);
    }
    let url = Url::parse(value).map_err(|_| WordPressReviewError::InvalidContext)?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.has_host()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err(WordPressReviewError::InvalidContext);
    }
    Ok(url)
}

fn validate_source_version(value: &str) -> Result<String, WordPressReviewError> {
    if value.is_empty()
        || value.len() > MAX_WORDPRESS_VERSION_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(WordPressReviewError::InvalidContext);
    }
    Ok(value.to_owned())
}

fn validate_identifier(value: &str) -> Result<(), WordPressReviewError> {
    if !valid_identifier(value) {
        return Err(WordPressReviewError::InvalidCatalog);
    }
    Ok(())
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_WORDPRESS_IDENTIFIER_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'@' | b'-')
        })
}

fn validate_text(value: &str, maximum: usize) -> Result<(), WordPressReviewError> {
    if value.is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        return Err(WordPressReviewError::InvalidCatalog);
    }
    Ok(())
}

fn valid_slug(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_WORDPRESS_SLUG_BYTES {
        return false;
    }
    let mut previous_hyphen = true;
    for byte in value.bytes() {
        match byte {
            b'a'..=b'z' | b'0'..=b'9' => previous_hyphen = false,
            b'-' if !previous_hyphen => previous_hyphen = true,
            _ => return false,
        }
    }
    !previous_hyphen
}

fn valid_cve(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("CVE-") else {
        return false;
    };
    let mut parts = rest.split('-');
    let (Some(year), Some(sequence), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    year.len() == 4
        && year.bytes().all(|byte| byte.is_ascii_digit())
        && (4..=10).contains(&sequence.len())
        && sequence.bytes().all(|byte| byte.is_ascii_digit())
}

fn validate_date(value: &str) -> Result<(), WordPressReviewError> {
    let bytes = value.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || !bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| matches!(index, 4 | 7) || byte.is_ascii_digit())
    {
        return Err(WordPressReviewError::InvalidCatalog);
    }
    let year = decimal(&bytes[0..4]).ok_or(WordPressReviewError::InvalidCatalog)?;
    let month = decimal(&bytes[5..7]).ok_or(WordPressReviewError::InvalidCatalog)?;
    let day = decimal(&bytes[8..10]).ok_or(WordPressReviewError::InvalidCatalog)?;
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let maximum = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return Err(WordPressReviewError::InvalidCatalog),
    };
    if day == 0 || day > maximum {
        return Err(WordPressReviewError::InvalidCatalog);
    }
    Ok(())
}

fn decimal(bytes: &[u8]) -> Option<u32> {
    bytes.iter().try_fold(0_u32, |value, digit| {
        value.checked_mul(10)?.checked_add(u32::from(*digit - b'0'))
    })
}

fn require_schema(value: &Value, expected: &str) -> Result<(), WordPressReviewError> {
    if value
        .as_object()
        .and_then(|object| object.get("schema"))
        .and_then(Value::as_str)
        != Some(expected)
    {
        return Err(WordPressReviewError::UnsupportedSchema);
    }
    Ok(())
}

fn parse_bounded_json(
    bytes: &[u8],
    maximum_bytes: usize,
    maximum_nodes: usize,
    maximum_array_length: usize,
    too_large: WordPressReviewError,
) -> Result<Value, WordPressReviewError> {
    if bytes.is_empty() {
        return Err(WordPressReviewError::EmptyInput);
    }
    if bytes.len() > maximum_bytes {
        return Err(too_large);
    }
    let limits = JsonLimits {
        maximum_nodes,
        maximum_array_length,
    };
    let mut budget = JsonBudget::default();
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let parsed = BoundedValueSeed {
        depth: 0,
        limits,
        budget: &mut budget,
    }
    .deserialize(&mut decoder)
    .map_err(classify_json_error)?;
    decoder.end().map_err(classify_json_error)?;
    Ok(parsed)
}

fn classify_json_error(error: serde_json::Error) -> WordPressReviewError {
    let message = error.to_string();
    if message.contains(DUPLICATE_KEY_MARKER) {
        WordPressReviewError::DuplicateKey
    } else if message.contains(JSON_LIMIT_MARKER) {
        WordPressReviewError::JsonLimitExceeded
    } else {
        WordPressReviewError::MalformedJson
    }
}

#[derive(Clone, Copy)]
struct JsonLimits {
    maximum_nodes: usize,
    maximum_array_length: usize,
}

#[derive(Default)]
struct JsonBudget {
    nodes: usize,
}

struct BoundedValueSeed<'a> {
    depth: usize,
    limits: JsonLimits,
    budget: &'a mut JsonBudget,
}

impl<'de> DeserializeSeed<'de> for BoundedValueSeed<'_> {
    type Value = Value;

    fn deserialize<D: de::Deserializer<'de>>(self, decoder: D) -> Result<Value, D::Error> {
        if self.depth > MAX_JSON_DEPTH || self.budget.nodes == self.limits.maximum_nodes {
            return Err(de::Error::custom(JSON_LIMIT_MARKER));
        }
        self.budget.nodes += 1;
        decoder.deserialize_any(BoundedValueVisitor {
            depth: self.depth,
            limits: self.limits,
            budget: self.budget,
        })
    }
}

struct BoundedValueVisitor<'a> {
    depth: usize,
    limits: JsonLimits,
    budget: &'a mut JsonBudget,
}

impl<'de> Visitor<'de> for BoundedValueVisitor<'_> {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded WordPress JSON")
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Value, E> {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| de::Error::custom("non-finite number"))
    }

    fn visit_borrowed_str<E: de::Error>(self, value: &'de str) -> Result<Value, E> {
        bounded_string(value)
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Value, E> {
        bounded_string(value)
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<Value, E> {
        if value.len() > MAX_JSON_STRING_BYTES {
            Err(de::Error::custom(JSON_LIMIT_MARKER))
        } else {
            Ok(Value::String(value))
        }
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut values: A) -> Result<Value, A::Error> {
        let mut array = Vec::new();
        let depth = self.depth;
        let limits = self.limits;
        let budget = self.budget;
        loop {
            if array.len() == limits.maximum_array_length {
                if values.next_element::<de::IgnoredAny>()?.is_some() {
                    return Err(de::Error::custom(JSON_LIMIT_MARKER));
                }
                break;
            }
            let Some(value) = values.next_element_seed(BoundedValueSeed {
                depth: depth + 1,
                limits,
                budget: &mut *budget,
            })?
            else {
                break;
            };
            array.push(value);
        }
        Ok(Value::Array(array))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut fields: A) -> Result<Value, A::Error> {
        let mut object = Map::new();
        let depth = self.depth;
        let limits = self.limits;
        let budget = self.budget;
        loop {
            if object.len() == MAX_JSON_OBJECT_FIELDS {
                if fields.next_key_seed(BoundedKeySeed)?.is_some() {
                    return Err(de::Error::custom(JSON_LIMIT_MARKER));
                }
                break;
            }
            let Some(key) = fields.next_key_seed(BoundedKeySeed)? else {
                break;
            };
            if object.contains_key(&key) {
                return Err(de::Error::custom(DUPLICATE_KEY_MARKER));
            }
            let value = fields.next_value_seed(BoundedValueSeed {
                depth: depth + 1,
                limits,
                budget: &mut *budget,
            })?;
            object.insert(key, value);
        }
        Ok(Value::Object(object))
    }
}

fn bounded_string<E: de::Error>(value: &str) -> Result<Value, E> {
    if value.len() > MAX_JSON_STRING_BYTES {
        Err(de::Error::custom(JSON_LIMIT_MARKER))
    } else {
        Ok(Value::String(value.to_owned()))
    }
}

struct BoundedKeySeed;

impl<'de> DeserializeSeed<'de> for BoundedKeySeed {
    type Value = String;

    fn deserialize<D: de::Deserializer<'de>>(self, decoder: D) -> Result<String, D::Error> {
        decoder.deserialize_str(BoundedKeyVisitor)
    }
}

struct BoundedKeyVisitor;

impl Visitor<'_> for BoundedKeyVisitor {
    type Value = String;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded JSON object key")
    }

    fn visit_borrowed_str<E: de::Error>(self, value: &str) -> Result<String, E> {
        self.visit_str(value)
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<String, E> {
        if value.len() > MAX_JSON_KEY_BYTES {
            Err(de::Error::custom(JSON_LIMIT_MARKER))
        } else {
            Ok(value.to_owned())
        }
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<String, E> {
        if value.len() > MAX_JSON_KEY_BYTES {
            Err(de::Error::custom(JSON_LIMIT_MARKER))
        } else {
            Ok(value)
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ContextWire {
    #[allow(dead_code)]
    schema: String,
    root: String,
    #[serde(default)]
    hosting_os: Option<HostingOsWire>,
    #[serde(default)]
    multisite: Option<MultisiteWire>,
    components: Vec<ContextComponentWire>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ContextComponentWire {
    kind: ComponentKindWire,
    slug: String,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    activation: Option<ActivationWire>,
    #[serde(default)]
    patches: Vec<PatchWire>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PatchWire {
    id: String,
    state: PatchStateWire,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogV1Wire {
    #[allow(dead_code)]
    schema: String,
    catalog: CatalogMetadataWire,
    records: Vec<AdvisoryRecordV1Wire>,
}

fn validate_profiled_range(
    range: RangeWire,
    profile: WordPressComparisonProfile,
) -> Result<WordPressProfiledAffectedRange, WordPressReviewError> {
    if range.lower.is_none() && range.upper.is_none() {
        return Err(WordPressReviewError::InvalidVersionRange);
    }
    let lower = range
        .lower
        .map(|endpoint| validate_profiled_endpoint(endpoint, profile))
        .transpose()?;
    let upper = range
        .upper
        .map(|endpoint| validate_profiled_endpoint(endpoint, profile))
        .transpose()?;
    if let (Some(lower), Some(upper)) = (&lower, &upper) {
        match lower
            .version
            .compare(&upper.version)
            .map_err(|_| WordPressReviewError::InvalidVersionRange)?
        {
            Ordering::Greater => return Err(WordPressReviewError::InvalidVersionRange),
            Ordering::Equal if !(lower.inclusive && upper.inclusive) => {
                return Err(WordPressReviewError::InvalidVersionRange);
            },
            Ordering::Less | Ordering::Equal => {},
        }
    }
    Ok(WordPressProfiledAffectedRange { lower, upper })
}

fn validate_profiled_endpoint(
    endpoint: EndpointWire,
    profile: WordPressComparisonProfile,
) -> Result<WordPressProfiledVersionEndpoint, WordPressReviewError> {
    let version = ProfiledVersionKey::parse(profile, &endpoint.version)
        .map_err(|_| WordPressReviewError::InvalidVersionRange)?;
    Ok(WordPressProfiledVersionEndpoint {
        declared: endpoint.version,
        version,
        inclusive: endpoint.inclusive,
    })
}

fn compare_profiled_ranges(
    left: &WordPressProfiledAffectedRange,
    right: &WordPressProfiledAffectedRange,
) -> Ordering {
    compare_profiled_endpoint_semantics(left.lower.as_ref(), right.lower.as_ref())
        .then_with(|| {
            compare_profiled_endpoint_semantics(left.upper.as_ref(), right.upper.as_ref())
        })
        .then_with(|| {
            compare_profiled_endpoint_spellings(left.lower.as_ref(), right.lower.as_ref())
        })
        .then_with(|| {
            compare_profiled_endpoint_spellings(left.upper.as_ref(), right.upper.as_ref())
        })
}

fn compare_profiled_endpoint_semantics(
    left: Option<&WordPressProfiledVersionEndpoint>,
    right: Option<&WordPressProfiledVersionEndpoint>,
) -> Ordering {
    match (left, right) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
        (Some(left), Some(right)) => left
            .version
            .compare(&right.version)
            .expect("one record has exactly one validated comparison profile")
            .then_with(|| left.inclusive.cmp(&right.inclusive)),
    }
}

fn compare_profiled_endpoint_spellings(
    left: Option<&WordPressProfiledVersionEndpoint>,
    right: Option<&WordPressProfiledVersionEndpoint>,
) -> Ordering {
    match (left, right) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
        (Some(left), Some(right)) => left.declared.cmp(&right.declared),
    }
}

fn profiled_ranges_equivalent(
    left: &WordPressProfiledAffectedRange,
    right: &WordPressProfiledAffectedRange,
) -> bool {
    profiled_endpoints_equivalent(left.lower.as_ref(), right.lower.as_ref())
        && profiled_endpoints_equivalent(left.upper.as_ref(), right.upper.as_ref())
}

fn profiled_endpoints_equivalent(
    left: Option<&WordPressProfiledVersionEndpoint>,
    right: Option<&WordPressProfiledVersionEndpoint>,
) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => {
            left.inclusive == right.inclusive
                && left.version.compare(&right.version).ok() == Some(Ordering::Equal)
        },
        (None, Some(_)) | (Some(_), None) => false,
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogV2Wire {
    #[allow(dead_code)]
    schema: String,
    catalog: CatalogMetadataWire,
    records: Vec<AdvisoryRecordV2Wire>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogMetadataWire {
    id: String,
    revision: String,
    retrieved_on: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdvisoryRecordV1Wire {
    id: String,
    component: ComponentIdentityWire,
    source: SourceWire,
    #[serde(default)]
    cve: Option<String>,
    summary: String,
    #[serde(default)]
    affected_ranges: Vec<RangeWire>,
    #[serde(default)]
    fixed_versions: Vec<String>,
    #[serde(default)]
    prerequisites: Vec<PrerequisiteWire>,
    #[serde(default)]
    remediation: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdvisoryRecordV2Wire {
    id: String,
    component: ComponentIdentityWire,
    source: SourceWire,
    comparison_profile: String,
    #[serde(default)]
    cve: Option<String>,
    summary: String,
    #[serde(default)]
    affected_ranges: Vec<RangeWire>,
    #[serde(default)]
    fixed_versions: Vec<String>,
    #[serde(default)]
    prerequisites: Vec<PrerequisiteWire>,
    #[serde(default)]
    remediation: Option<String>,
}

struct AdvisoryRecordInput {
    id: String,
    component: ComponentIdentityWire,
    source: SourceWire,
    comparison_profile: WordPressComparisonProfile,
    cve: Option<String>,
    summary: String,
    affected_ranges: Vec<RangeWire>,
    fixed_versions: Vec<String>,
    prerequisites: Vec<PrerequisiteWire>,
    remediation: Option<String>,
}

impl From<AdvisoryRecordV1Wire> for AdvisoryRecordInput {
    fn from(record: AdvisoryRecordV1Wire) -> Self {
        Self {
            id: record.id,
            component: record.component,
            source: record.source,
            comparison_profile: WordPressComparisonProfile::NumericDottedV1,
            cve: record.cve,
            summary: record.summary,
            affected_ranges: record.affected_ranges,
            fixed_versions: record.fixed_versions,
            prerequisites: record.prerequisites,
            remediation: record.remediation,
        }
    }
}

impl TryFrom<AdvisoryRecordV2Wire> for AdvisoryRecordInput {
    type Error = WordPressReviewError;

    fn try_from(record: AdvisoryRecordV2Wire) -> Result<Self, Self::Error> {
        Ok(Self {
            id: record.id,
            component: record.component,
            source: record.source,
            comparison_profile: WordPressComparisonProfile::parse(&record.comparison_profile)
                .map_err(|_| WordPressReviewError::InvalidCatalog)?,
            cve: record.cve,
            summary: record.summary,
            affected_ranges: record.affected_ranges,
            fixed_versions: record.fixed_versions,
            prerequisites: record.prerequisites,
            remediation: record.remediation,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ComponentIdentityWire {
    kind: ComponentKindWire,
    slug: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceWire {
    reference: String,
    revision: String,
    retrieved_on: String,
    usage_basis: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RangeWire {
    #[serde(default)]
    lower: Option<EndpointWire>,
    #[serde(default)]
    upper: Option<EndpointWire>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EndpointWire {
    version: String,
    inclusive: bool,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum PrerequisiteWire {
    HostingOs { equals: HostingOsWire },
    Multisite { equals: MultisiteWire },
    Activation { equals: ActivationWire },
    Patch { id: String, equals: PatchStateWire },
    Unsupported { name: String },
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ComponentKindWire {
    Core,
    Plugin,
    Theme,
}

impl From<ComponentKindWire> for WordPressComponentKind {
    fn from(value: ComponentKindWire) -> Self {
        match value {
            ComponentKindWire::Core => Self::Core,
            ComponentKindWire::Plugin => Self::Plugin,
            ComponentKindWire::Theme => Self::Theme,
        }
    }
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum HostingOsWire {
    Linux,
    Windows,
    Macos,
    Bsd,
    Other,
}

impl From<HostingOsWire> for WordPressHostingOs {
    fn from(value: HostingOsWire) -> Self {
        match value {
            HostingOsWire::Linux => Self::Linux,
            HostingOsWire::Windows => Self::Windows,
            HostingOsWire::Macos => Self::Macos,
            HostingOsWire::Bsd => Self::Bsd,
            HostingOsWire::Other => Self::Other,
        }
    }
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum MultisiteWire {
    Enabled,
    Disabled,
}

impl From<MultisiteWire> for WordPressMultisiteState {
    fn from(value: MultisiteWire) -> Self {
        match value {
            MultisiteWire::Enabled => Self::Enabled,
            MultisiteWire::Disabled => Self::Disabled,
        }
    }
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ActivationWire {
    Active,
    Inactive,
    NetworkActive,
    Unknown,
}

impl From<ActivationWire> for WordPressActivationState {
    fn from(value: ActivationWire) -> Self {
        match value {
            ActivationWire::Active => Self::Active,
            ActivationWire::Inactive => Self::Inactive,
            ActivationWire::NetworkActive => Self::NetworkActive,
            ActivationWire::Unknown => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PatchStateWire {
    Applied,
    NotApplied,
    Unknown,
}

impl From<PatchStateWire> for WordPressPatchState {
    fn from(value: PatchStateWire) -> Self {
        match value {
            PatchStateWire::Applied => Self::Applied,
            PatchStateWire::NotApplied => Self::NotApplied,
            PatchStateWire::Unknown => Self::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wordfence_associations(count: usize) -> String {
        use std::fmt::Write as _;

        let mut document = String::from("{");
        for index in 0..count {
            if index != 0 {
                document.push(',');
            }
            let id = format!("00000000-0000-4000-8000-{index:012x}");
            write!(
                document,
                r#""{id}":{{"id":"{id}","title":"Synthetic","software":[{{"type":"plugin","name":"Synthetic","slug":"selected-plugin","affected_versions":{{"all":{{"from_version":"*","from_inclusive":false,"to_version":"*","to_inclusive":false}}}},"patched":false,"patched_versions":[],"remediation":"Review source guidance"}}],"informational":false,"description":"Synthetic bounded evaluator fixture","references":["https://example.invalid/{id}"],"cwe":null,"cvss":null,"cve":null,"cve_link":null,"researchers":[],"published":null,"updated":null,"copyrights":null}}"#
            )
            .unwrap();
        }
        document.push('}');
        document
    }

    const CONTEXT: &str = r#"{
      "schema":"security.wordpress-context/v1",
      "root":"https://example.test/",
      "hosting_os":"linux",
      "multisite":"enabled",
      "components":[
        {"kind":"core","slug":"wordpress","version":"6.9.4","activation":"active"},
        {"kind":"plugin","slug":"sample-plugin","version":"2.4.0","activation":"network_active",
         "patches":[{"id":"vendor-backport-1","state":"applied"}]},
        {"kind":"theme","slug":"sample-theme","activation":"inactive"}
      ]
    }"#;

    const CATALOG: &str = r#"{
      "schema":"security.wordpress-advisory-catalog/v1",
      "catalog":{"id":"synthetic-wordpress-catalog","revision":"r1","retrieved_on":"2026-09-06"},
      "records":[
        {
          "id":"SYNTHETIC-CORE-1",
          "component":{"kind":"core","slug":"wordpress"},
          "source":{"reference":"https://example.test/advisories/core-1","revision":"r1","retrieved_on":"2026-09-06","usage_basis":"synthetic test record"},
          "cve":"CVE-2099-1000",
          "summary":"Synthetic bounded core record",
          "affected_ranges":[
            {"lower":{"version":"6.9.0","inclusive":true},"upper":{"version":"6.9.5","inclusive":false}},
            {"lower":{"version":"7.0.0","inclusive":true},"upper":{"version":"7.0.2","inclusive":false}}
          ],
          "fixed_versions":["6.9.5","7.0.2"],
          "prerequisites":[{"kind":"hosting_os","equals":"linux"},{"kind":"multisite","equals":"enabled"}],
          "remediation":"Follow the cited vendor guidance"
        },
        {
          "id":"SYNTHETIC-PLUGIN-1",
          "component":{"kind":"plugin","slug":"sample-plugin"},
          "source":{"reference":"https://example.test/advisories/plugin-1","revision":"r2","retrieved_on":"2026-09-06","usage_basis":"synthetic test record"},
          "summary":"Synthetic plugin record",
          "affected_ranges":[{"upper":{"version":"2.5.0","inclusive":false}}],
          "fixed_versions":["2.5.0"],
          "prerequisites":[{"kind":"activation","equals":"network_active"},{"kind":"patch","id":"vendor-backport-1","equals":"not_applied"}]
        }
      ]
    }"#;

    const PROFILED_CONTEXT: &str = r#"{
      "schema":"security.wordpress-context/v1",
      "root":"https://example.test/",
      "hosting_os":"linux",
      "components":[
        {"kind":"core","slug":"wordpress","version":"2.4.0-beta1","activation":"active"}
      ]
    }"#;

    const PROFILED_CATALOG: &str = r#"{
      "schema":"security.wordpress-advisory-catalog/v2",
      "catalog":{"id":"synthetic-wordpress-profiled-catalog","revision":"r2","retrieved_on":"2026-09-07"},
      "records":[
        {
          "id":"SYNTHETIC-NUMERIC-BETA",
          "component":{"kind":"core","slug":"wordpress"},
          "source":{"reference":"https://example.test/advisories/numeric-beta","revision":"r2","retrieved_on":"2026-09-07","usage_basis":"fictional numeric-profile test record"},
          "comparison_profile":"numeric-dotted/v1",
          "summary":"Synthetic numeric profile record",
          "affected_ranges":[{"lower":{"version":"2.0.0","inclusive":true},"upper":{"version":"3.0.0","inclusive":false}}],
          "fixed_versions":["3.0.0"]
        },
        {
          "id":"SYNTHETIC-PHP-BETA",
          "component":{"kind":"core","slug":"wordpress"},
          "source":{"reference":"https://example.test/advisories/php-beta","revision":"r2","retrieved_on":"2026-09-07","usage_basis":"fictional PHP-subset test record"},
          "comparison_profile":"php-release-subset/v1",
          "summary":"Synthetic PHP release-subset profile record",
          "affected_ranges":[{"lower":{"version":"2.4.0-beta0","inclusive":true},"upper":{"version":"2.4.0","inclusive":false}}],
          "fixed_versions":["2.4.0"],
          "prerequisites":[{"kind":"hosting_os","equals":"linux"}]
        }
      ]
    }"#;

    fn inputs() -> WordPressReviewInputs {
        WordPressReviewInputs::new(
            Some(parse_wordpress_context(CONTEXT.as_bytes()).unwrap()),
            Some(parse_wordpress_advisory_catalog(CATALOG.as_bytes()).unwrap()),
        )
    }

    #[test]
    fn committed_context_and_catalog_examples_match_the_strict_v1_contract() {
        let context = parse_wordpress_context(include_bytes!(
            "../../../docs/examples/wordpress-review/context.synthetic.json"
        ))
        .unwrap();
        let curated = parse_wordpress_advisory_catalog(include_bytes!(
            "../../../docs/examples/wordpress-review/advisories.curated.json"
        ))
        .unwrap();
        let synthetic = parse_wordpress_advisory_catalog(include_bytes!(
            "../../../docs/examples/wordpress-review/advisories.synthetic.json"
        ))
        .unwrap();

        assert_eq!(context.components().len(), 4);
        assert_eq!(curated.records().len(), 1);
        assert_eq!(curated.records()[0].id(), "GHSA-fpp7-x2x2-2mjf");
        assert_eq!(synthetic.records().len(), 3);
        assert!(synthetic
            .records()
            .iter()
            .all(|record| record.id().starts_with("SYNTHETIC-")));
    }

    #[test]
    fn context_parser_retains_typed_assertions_and_exact_root() {
        let context = parse_wordpress_context(CONTEXT.as_bytes()).unwrap();
        assert_eq!(context.root_url().as_str(), "https://example.test/");
        assert_eq!(context.hosting_os(), Some(WordPressHostingOs::Linux));
        assert_eq!(context.multisite(), Some(WordPressMultisiteState::Enabled));
        assert_eq!(context.components().len(), 3);
        assert_eq!(context.components()[1].identity().slug(), "sample-plugin");
        assert_eq!(
            context.components()[1].patches()[0].id(),
            "vendor-backport-1"
        );
    }

    #[test]
    fn context_rejects_duplicate_keys_identities_and_non_root_authority() {
        let duplicate_key = CONTEXT.replacen(
            "\"root\":\"https://example.test/\"",
            "\"root\":\"https://example.test/\",\"root\":\"https://other.test/\"",
            1,
        );
        assert_eq!(
            parse_wordpress_context(duplicate_key.as_bytes()),
            Err(WordPressReviewError::DuplicateKey)
        );
        let duplicate_component = CONTEXT.replace(
            "{\"kind\":\"theme\",\"slug\":\"sample-theme\",\"activation\":\"inactive\"}",
            "{\"kind\":\"core\",\"slug\":\"wordpress\",\"version\":\"6.9.4\"}",
        );
        assert_eq!(
            parse_wordpress_context(duplicate_component.as_bytes()),
            Err(WordPressReviewError::DuplicateComponent)
        );
        for root in [
            "https://user@example.test/",
            "https://example.test/subpath",
            "https://example.test/?query=value",
            "file:///tmp/site",
        ] {
            let document = CONTEXT.replace("https://example.test/", root);
            assert!(matches!(
                parse_wordpress_context(document.as_bytes()),
                Err(WordPressReviewError::InvalidContext)
            ));
        }
    }

    #[test]
    fn context_limits_are_enforced_before_model_construction() {
        assert_eq!(
            parse_wordpress_context(&vec![b' '; MAX_WORDPRESS_CONTEXT_BYTES + 1]),
            Err(WordPressReviewError::ContextTooLarge)
        );
        let components = (0..=MAX_WORDPRESS_CONTEXT_COMPONENTS)
            .map(|index| format!(r#"{{"kind":"plugin","slug":"plugin-{index}"}}"#))
            .collect::<Vec<_>>()
            .join(",");
        let document = format!(
            r#"{{"schema":"{WORDPRESS_CONTEXT_SCHEMA}","root":"https://example.test/","components":[{components}]}}"#
        );
        assert!(matches!(
            parse_wordpress_context(document.as_bytes()),
            Err(WordPressReviewError::JsonLimitExceeded | WordPressReviewError::InvalidContext)
        ));
    }

    #[test]
    fn catalog_parser_retains_disjoint_ranges_and_source_basis() {
        let catalog = parse_wordpress_advisory_catalog(CATALOG.as_bytes()).unwrap();
        assert_eq!(catalog.metadata().id(), "synthetic-wordpress-catalog");
        assert_eq!(catalog.records().len(), 2);
        assert_eq!(catalog.records()[0].affected_ranges().len(), 2);
        assert_eq!(
            catalog.records()[0].source().reference(),
            "https://example.test/advisories/core-1"
        );
        assert_eq!(catalog.records()[0].fixed_versions(), ["6.9.5", "7.0.2"]);
    }

    #[test]
    fn catalog_v2_requires_one_explicit_supported_profile_per_record() {
        let catalog = parse_wordpress_advisory_catalog(PROFILED_CATALOG.as_bytes()).unwrap();
        assert_eq!(catalog.schema(), WordPressAdvisoryCatalogSchema::V2);
        assert_eq!(catalog.records().len(), 2);
        assert_eq!(
            catalog.records()[0].comparison_profile(),
            WordPressComparisonProfile::NumericDottedV1
        );
        assert_eq!(
            catalog.records()[1].comparison_profile(),
            WordPressComparisonProfile::PhpReleaseSubsetV1
        );
        assert!(catalog
            .records()
            .iter()
            .all(|record| record.affected_ranges().is_empty()));
        assert!(catalog
            .records()
            .iter()
            .all(|record| record.profiled_affected_ranges().len() == 1));

        let v1_with_profile = CATALOG.replacen(
            "\"summary\":\"Synthetic bounded core record\"",
            "\"comparison_profile\":\"numeric-dotted/v1\",\"summary\":\"Synthetic bounded core record\"",
            1,
        );
        assert_eq!(
            parse_wordpress_advisory_catalog(v1_with_profile.as_bytes()),
            Err(WordPressReviewError::InvalidCatalog)
        );

        let v2_without_profile =
            PROFILED_CATALOG.replacen("\"comparison_profile\":\"numeric-dotted/v1\",", "", 1);
        assert_eq!(
            parse_wordpress_advisory_catalog(v2_without_profile.as_bytes()),
            Err(WordPressReviewError::InvalidCatalog)
        );

        let v2_unknown_profile = PROFILED_CATALOG.replacen("numeric-dotted/v1", "semver/v1", 1);
        assert_eq!(
            parse_wordpress_advisory_catalog(v2_unknown_profile.as_bytes()),
            Err(WordPressReviewError::InvalidCatalog)
        );
    }

    #[test]
    fn profiled_evaluation_interprets_beta_only_under_the_selected_profile() {
        let inputs = WordPressReviewInputs::new(
            Some(parse_wordpress_context(PROFILED_CONTEXT.as_bytes()).unwrap()),
            Some(parse_wordpress_advisory_catalog(PROFILED_CATALOG.as_bytes()).unwrap()),
        );
        let signals = [WordPressComponentSignal::generator_metadata(Some("2.4.0-beta1")).unwrap()];
        let result = evaluate_wordpress_review(&signals, &inputs).unwrap();
        assert!(result.components().iter().all(|component| {
            component.evidence_class() != WordPressComponentEvidenceClass::Conflicting
        }));

        assert_eq!(
            result.catalog_schema(),
            Some(WordPressAdvisoryCatalogSchema::V2)
        );
        let numeric = result
            .advisories()
            .iter()
            .find(|evaluation| evaluation.record().id() == "SYNTHETIC-NUMERIC-BETA")
            .unwrap();
        assert_eq!(
            numeric.version_resolution(),
            Some(WordPressVersionResolution::Unsupported)
        );
        assert_eq!(
            numeric.version_resolution_reason(),
            Some(WordPressVersionResolutionReason::UnsupportedVersionEvidence)
        );
        assert_eq!(
            numeric.version_relation(),
            WordPressVersionRelation::Unsupported
        );
        assert_eq!(
            numeric.applicability(),
            WordPressApplicability::IndeterminateUnsupported
        );

        let php = result
            .advisories()
            .iter()
            .find(|evaluation| evaluation.record().id() == "SYNTHETIC-PHP-BETA")
            .unwrap();
        assert_eq!(
            php.version_resolution(),
            Some(WordPressVersionResolution::SupportedEquivalent)
        );
        assert_eq!(
            php.version_resolution_reason(),
            Some(WordPressVersionResolutionReason::EquivalentSupportedVersions)
        );
        assert_eq!(
            php.version_relation(),
            WordPressVersionRelation::WithinDeclaredRange
        );
        assert_eq!(
            php.prerequisites()[0].outcome(),
            WordPressPrerequisiteOutcome::MatchedOnSuppliedFacts
        );
        assert_eq!(
            php.applicability(),
            WordPressApplicability::CandidateMatchOnDeclaredFacts
        );
        assert_eq!(
            php.exploit_execution(),
            WordPressExecutionStatus::NotPerformed
        );
        assert_eq!(
            php.impact_validation(),
            WordPressExecutionStatus::NotPerformed
        );
    }

    #[test]
    fn profiled_aliases_keep_component_provenance_separate_from_record_resolution() {
        let context = PROFILED_CONTEXT.replacen("2.4.0-beta1", "2.4.0+beta1", 1);
        let inputs = WordPressReviewInputs::new(
            Some(parse_wordpress_context(context.as_bytes()).unwrap()),
            Some(parse_wordpress_advisory_catalog(PROFILED_CATALOG.as_bytes()).unwrap()),
        );
        let signals = [WordPressComponentSignal::generator_metadata(Some("2.4.0-beta1")).unwrap()];
        let result = evaluate_wordpress_review(&signals, &inputs).unwrap();
        let component = result
            .components()
            .iter()
            .find(|component| component.identity().kind() == WordPressComponentKind::Core)
            .unwrap();
        assert_eq!(
            component.evidence_class(),
            WordPressComponentEvidenceClass::ObservedHint
        );

        let numeric = result
            .advisories()
            .iter()
            .find(|evaluation| evaluation.record().id() == "SYNTHETIC-NUMERIC-BETA")
            .unwrap();
        assert_eq!(
            numeric.version_resolution(),
            Some(WordPressVersionResolution::Unsupported)
        );
        let php = result
            .advisories()
            .iter()
            .find(|evaluation| evaluation.record().id() == "SYNTHETIC-PHP-BETA")
            .unwrap();
        assert_eq!(
            php.version_resolution(),
            Some(WordPressVersionResolution::SupportedEquivalent)
        );
        assert_eq!(
            php.version_resolution_reason(),
            Some(WordPressVersionResolutionReason::EquivalentSupportedVersions)
        );
    }

    #[test]
    fn unsupported_profiled_evidence_is_not_invented_as_a_semantic_conflict() {
        let context = PROFILED_CONTEXT.replacen("2.4.0-beta1", "2.4.0-vendor-a", 1);
        let inputs = WordPressReviewInputs::new(
            Some(parse_wordpress_context(context.as_bytes()).unwrap()),
            Some(parse_wordpress_advisory_catalog(PROFILED_CATALOG.as_bytes()).unwrap()),
        );
        let signals =
            [WordPressComponentSignal::generator_metadata(Some("2.4.0-vendor-b")).unwrap()];
        let result = evaluate_wordpress_review(&signals, &inputs).unwrap();
        for advisory in result.advisories() {
            assert_eq!(
                advisory.version_resolution(),
                Some(WordPressVersionResolution::Unsupported)
            );
            assert_eq!(
                advisory.version_resolution_reason(),
                Some(WordPressVersionResolutionReason::UnsupportedVersionEvidence)
            );
            assert_eq!(
                advisory.applicability(),
                WordPressApplicability::IndeterminateUnsupported
            );
        }

        let mixed_signals =
            [WordPressComponentSignal::generator_metadata(Some("2.4.0-beta1")).unwrap()];
        let mixed = evaluate_wordpress_review(&mixed_signals, &inputs).unwrap();
        for advisory in mixed.advisories() {
            assert_eq!(
                advisory.version_resolution(),
                Some(WordPressVersionResolution::Unsupported)
            );
            assert_eq!(
                advisory.version_resolution_reason(),
                Some(WordPressVersionResolutionReason::UnsupportedVersionEvidence)
            );
        }
    }

    #[test]
    fn version_evidence_resolution_is_profile_specific() {
        let catalog = r#"{
          "schema":"security.wordpress-advisory-catalog/v2",
          "catalog":{"id":"synthetic-profile-resolution","revision":"r1","retrieved_on":"2026-09-07"},
          "records":[
            {
              "id":"SYNTHETIC-NUMERIC-TRAILING-ZERO",
              "component":{"kind":"core","slug":"wordpress"},
              "source":{"reference":"https://example.test/advisories/numeric-zero","revision":"r1","retrieved_on":"2026-09-07","usage_basis":"fictional profile-resolution test"},
              "comparison_profile":"numeric-dotted/v1",
              "summary":"Synthetic numeric trailing-zero record",
              "affected_ranges":[{"lower":{"version":"1.0","inclusive":true},"upper":{"version":"1.0.0","inclusive":true}}]
            },
            {
              "id":"SYNTHETIC-PHP-TRAILING-ZERO",
              "component":{"kind":"core","slug":"wordpress"},
              "source":{"reference":"https://example.test/advisories/php-zero","revision":"r1","retrieved_on":"2026-09-07","usage_basis":"fictional profile-resolution test"},
              "comparison_profile":"php-release-subset/v1",
              "summary":"Synthetic PHP trailing-zero record",
              "affected_ranges":[{"lower":{"version":"1.0","inclusive":true},"upper":{"version":"1.0.0","inclusive":true}}]
            }
          ]
        }"#;
        let context = r#"{
          "schema":"security.wordpress-context/v1",
          "root":"https://example.test/",
          "components":[{"kind":"core","slug":"wordpress","version":"1.0.0"}]
        }"#;
        let inputs = WordPressReviewInputs::new(
            Some(parse_wordpress_context(context.as_bytes()).unwrap()),
            Some(parse_wordpress_advisory_catalog(catalog.as_bytes()).unwrap()),
        );
        let signals = [WordPressComponentSignal::generator_metadata(Some("1.0")).unwrap()];
        let result = evaluate_wordpress_review(&signals, &inputs).unwrap();
        let numeric = result
            .advisories()
            .iter()
            .find(|evaluation| evaluation.record().id().contains("NUMERIC"))
            .unwrap();
        assert_eq!(
            numeric.version_resolution(),
            Some(WordPressVersionResolution::SupportedEquivalent)
        );
        assert_eq!(
            numeric.version_resolution_reason(),
            Some(WordPressVersionResolutionReason::EquivalentSupportedVersions)
        );
        assert_eq!(
            numeric.version_relation(),
            WordPressVersionRelation::WithinDeclaredRange
        );

        let php = result
            .advisories()
            .iter()
            .find(|evaluation| evaluation.record().id().contains("PHP"))
            .unwrap();
        assert_eq!(
            php.version_resolution(),
            Some(WordPressVersionResolution::Conflicting)
        );
        assert_eq!(
            php.version_resolution_reason(),
            Some(WordPressVersionResolutionReason::ConflictingVersionEvidence)
        );
        assert_eq!(php.version_relation(), WordPressVersionRelation::Unknown);
        assert_eq!(
            php.applicability(),
            WordPressApplicability::IndeterminateMissingEvidence
        );
    }

    #[test]
    fn profiled_ranges_and_fixed_versions_use_semantic_profile_equality() {
        let exclusive_equal_aliases = PROFILED_CATALOG
            .replacen("2.4.0-beta0", "1.0-alpha1", 1)
            .replacen(
                "2.4.0\",\"inclusive\":false",
                "1.0a1\",\"inclusive\":false",
                1,
            );
        assert_eq!(
            parse_wordpress_advisory_catalog(exclusive_equal_aliases.as_bytes()),
            Err(WordPressReviewError::InvalidVersionRange)
        );

        let duplicate_fixed_aliases = PROFILED_CATALOG.replacen(
            "\"fixed_versions\":[\"2.4.0\"]",
            "\"fixed_versions\":[\"2.4.0-alpha1\",\"2.4.0a1\"]",
            1,
        );
        assert_eq!(
            parse_wordpress_advisory_catalog(duplicate_fixed_aliases.as_bytes()),
            Err(WordPressReviewError::InvalidCatalog)
        );

        let php_record = parse_wordpress_advisory_catalog(PROFILED_CATALOG.as_bytes())
            .unwrap()
            .records()
            .iter()
            .find(|record| record.id() == "SYNTHETIC-PHP-BETA")
            .unwrap()
            .clone();
        assert_eq!(
            php_record.compare_versions("1.0+beta1", "1.0-beta1"),
            Some(Ordering::Equal)
        );
        assert_eq!(
            php_record.compare_versions("1.0", "1.0.0"),
            Some(Ordering::Less)
        );
        assert_eq!(php_record.compare_versions("1.0-vendor1", "1.0"), None);

        let mut interleaved_aliases: Value = serde_json::from_str(PROFILED_CATALOG).unwrap();
        interleaved_aliases["records"][1]["affected_ranges"] = serde_json::json!([
            {
                "lower":{"version":"1.0-alpha1","inclusive":true},
                "upper":{"version":"3.0","inclusive":false}
            },
            {
                "lower":{"version":"1.0-alpha1","inclusive":true},
                "upper":{"version":"4.0","inclusive":false}
            },
            {
                "lower":{"version":"1.0a1","inclusive":true},
                "upper":{"version":"3.0","inclusive":false}
            }
        ]);
        let bytes = serde_json::to_vec(&interleaved_aliases).unwrap();
        let catalogue = parse_wordpress_advisory_catalog(&bytes).unwrap();
        let ranges = catalogue
            .records()
            .iter()
            .find(|record| record.id() == "SYNTHETIC-PHP-BETA")
            .unwrap()
            .profiled_affected_ranges();
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0].lower().unwrap().declared(), "1.0-alpha1");
        assert_eq!(ranges[0].upper().unwrap().declared(), "3.0");
    }

    #[test]
    fn catalog_rejects_duplicates_unknown_fields_and_malformed_ranges() {
        let duplicate = CATALOG.replacen(
            "\"summary\":\"Synthetic bounded core record\"",
            "\"summary\":\"Synthetic bounded core record\",\"summary\":\"other\"",
            1,
        );
        assert_eq!(
            parse_wordpress_advisory_catalog(duplicate.as_bytes()),
            Err(WordPressReviewError::DuplicateKey)
        );
        let unknown = CATALOG.replacen(
            "\"summary\":\"Synthetic bounded core record\"",
            "\"summary\":\"Synthetic bounded core record\",\"predicate\":\"execute-me\"",
            1,
        );
        assert_eq!(
            parse_wordpress_advisory_catalog(unknown.as_bytes()),
            Err(WordPressReviewError::InvalidCatalog)
        );
        let backwards = CATALOG.replacen("6.9.0", "6.9.9", 1);
        assert_eq!(
            parse_wordpress_advisory_catalog(backwards.as_bytes()),
            Err(WordPressReviewError::InvalidVersionRange)
        );
        let inferred_range = CATALOG.replacen(
            "{\"lower\":{\"version\":\"6.9.0\",\"inclusive\":true},\"upper\":{\"version\":\"6.9.5\",\"inclusive\":false}}",
            "{}",
            1,
        );
        assert_eq!(
            parse_wordpress_advisory_catalog(inferred_range.as_bytes()),
            Err(WordPressReviewError::InvalidVersionRange)
        );
    }

    #[test]
    fn numeric_dotted_profile_has_explicit_trailing_zero_and_boundary_semantics() {
        let one_two = NumericDottedVersion::parse("1.2").unwrap();
        let one_two_zero = NumericDottedVersion::parse("1.2.0").unwrap();
        assert_eq!(one_two, one_two_zero);
        assert!(NumericDottedVersion::parse("1.2.1").unwrap() > one_two);
        for unsupported in ["1.2-beta", "v1.2", "1..2", "01.2", "4294967296"] {
            assert_eq!(
                NumericDottedVersion::parse(unsupported),
                Err(NumericDottedVersionError)
            );
        }

        let catalog = parse_wordpress_advisory_catalog(CATALOG.as_bytes()).unwrap();
        let range = &catalog.records()[0].affected_ranges()[0];
        assert!(range.contains(&NumericDottedVersion::parse("6.9.0").unwrap()));
        assert!(range.contains(&NumericDottedVersion::parse("6.9.4").unwrap()));
        assert!(!range.contains(&NumericDottedVersion::parse("6.9.5").unwrap()));
        assert!(!range.contains(&NumericDottedVersion::parse("7.0.1").unwrap()));
    }

    #[test]
    fn explicit_endpoint_inclusivity_and_missing_ranges_remain_distinct() {
        let inclusive_upper = CATALOG.replacen(
            "\"version\":\"6.9.5\",\"inclusive\":false",
            "\"version\":\"6.9.5\",\"inclusive\":true",
            1,
        );
        let catalog = parse_wordpress_advisory_catalog(inclusive_upper.as_bytes()).unwrap();
        assert!(catalog.records()[0].affected_ranges()[0]
            .contains(&NumericDottedVersion::parse("6.9.5").unwrap()));

        let no_ranges = CATALOG.replacen(
            r#""affected_ranges":[
            {"lower":{"version":"6.9.0","inclusive":true},"upper":{"version":"6.9.5","inclusive":false}},
            {"lower":{"version":"7.0.0","inclusive":true},"upper":{"version":"7.0.2","inclusive":false}}
          ]"#,
            r#""affected_ranges":[]"#,
            1,
        );
        let inputs = WordPressReviewInputs::new(
            Some(parse_wordpress_context(CONTEXT.as_bytes()).unwrap()),
            Some(parse_wordpress_advisory_catalog(no_ranges.as_bytes()).unwrap()),
        );
        let result = evaluate_wordpress_review(&[], &inputs).unwrap();
        assert_eq!(
            result.advisories()[0].version_relation(),
            WordPressVersionRelation::Unknown,
            "a documented fixed version must not invent an affected interval"
        );
    }

    #[test]
    fn evaluator_separates_observation_operator_source_and_candidate_applicability() {
        let signals = [WordPressComponentSignal::generator_metadata(Some("6.9.4")).unwrap()];
        let result = evaluate_wordpress_review(&signals, &inputs()).unwrap();
        assert_eq!(result.catalog_status(), WordPressCatalogStatus::Evaluated);
        assert_eq!(result.catalog_metadata().unwrap().revision(), "r1");
        let core = result
            .components()
            .iter()
            .find(|component| component.identity().kind() == WordPressComponentKind::Core)
            .unwrap();
        assert_eq!(
            core.evidence_class(),
            WordPressComponentEvidenceClass::ObservedHint
        );
        assert_eq!(
            core.identity_sources(),
            [
                WordPressEvidenceSource::GeneratorMetadata,
                WordPressEvidenceSource::OperatorContext,
            ]
        );
        assert_eq!(
            core.confidence_classes(),
            [
                WordPressEvidenceConfidence::PublicDeclaration,
                WordPressEvidenceConfidence::OperatorAssertion,
            ]
        );
        assert_eq!(
            core.versions()[0].confidence(),
            WordPressEvidenceConfidence::PublicDeclaration
        );
        let core_advisory = &result.advisories()[0];
        assert_eq!(
            core_advisory.version_relation(),
            WordPressVersionRelation::WithinDeclaredRange
        );
        assert_eq!(
            core_advisory.applicability(),
            WordPressApplicability::CandidateMatchOnDeclaredFacts
        );
        assert_eq!(
            core_advisory.exploit_execution(),
            WordPressExecutionStatus::NotPerformed
        );
        assert_eq!(
            core_advisory.impact_validation(),
            WordPressExecutionStatus::NotPerformed
        );
    }

    #[test]
    fn repeated_hints_do_not_become_independent_evidence() {
        let signal = WordPressComponentSignal::same_origin_asset(
            WordPressComponentKind::Plugin,
            "sample-plugin",
        )
        .unwrap();
        let result = evaluate_wordpress_review(
            &[signal.clone(), signal.clone(), signal],
            &WordPressReviewInputs::default(),
        )
        .unwrap();
        assert_eq!(result.components().len(), 1);
        assert_eq!(
            result.components()[0].identity_sources(),
            [WordPressEvidenceSource::SameOriginAssetPath]
        );
        assert!(result.components()[0].versions().is_empty());

        let core = WordPressComponentSignal::core_asset();
        assert_eq!(core.identity(), &WordPressComponentIdentity::core());
        assert_eq!(core.source(), WordPressEvidenceSource::SameOriginAssetPath);
        assert_eq!(
            core.confidence(),
            WordPressEvidenceConfidence::StructuralHint
        );
    }

    #[test]
    fn contradictory_versions_are_not_resolved_by_last_write() {
        let signals = [WordPressComponentSignal::generator_metadata(Some("6.9.3")).unwrap()];
        let result = evaluate_wordpress_review(&signals, &inputs()).unwrap();
        assert_eq!(
            result.components()[0].evidence_class(),
            WordPressComponentEvidenceClass::Conflicting
        );
        assert_eq!(
            result.advisories()[0].version_relation(),
            WordPressVersionRelation::Unknown
        );
        assert_eq!(
            result.advisories()[0].applicability(),
            WordPressApplicability::IndeterminateMissingEvidence
        );
    }

    #[test]
    fn unsupported_observed_version_stays_indeterminate() {
        let context = CONTEXT.replace("6.9.4", "6.9.4-RC1");
        let inputs = WordPressReviewInputs::new(
            Some(parse_wordpress_context(context.as_bytes()).unwrap()),
            Some(parse_wordpress_advisory_catalog(CATALOG.as_bytes()).unwrap()),
        );
        let result = evaluate_wordpress_review(&[], &inputs).unwrap();
        assert_eq!(
            result.advisories()[0].version_relation(),
            WordPressVersionRelation::Unsupported
        );
        assert_eq!(
            result.advisories()[0].applicability(),
            WordPressApplicability::IndeterminateUnsupported
        );
    }

    #[test]
    fn prerequisite_outcomes_do_not_turn_conflicts_into_security_claims() {
        let result = evaluate_wordpress_review(&[], &inputs()).unwrap();
        let plugin = result
            .advisories()
            .iter()
            .find(|evaluation| evaluation.record().id() == "SYNTHETIC-PLUGIN-1")
            .unwrap();
        assert_eq!(
            plugin.prerequisites()[0].outcome(),
            WordPressPrerequisiteOutcome::MatchedOnSuppliedFacts
        );
        assert_eq!(
            plugin.prerequisites()[1].outcome(),
            WordPressPrerequisiteOutcome::ContradictedOnSuppliedFacts
        );
        assert_eq!(
            plugin.applicability(),
            WordPressApplicability::ContradictedByDeclaredFacts
        );
    }

    #[test]
    fn a_contradicted_requirement_dominates_an_unresolved_unsupported_requirement() {
        let catalogue = CATALOG.replacen(
            r#"{"kind":"multisite","equals":"enabled"}"#,
            r#"{"kind":"multisite","equals":"disabled"},{"kind":"unsupported","name":"vendor_specific_runtime_state"}"#,
            1,
        );
        let inputs = WordPressReviewInputs::new(
            Some(parse_wordpress_context(CONTEXT.as_bytes()).unwrap()),
            Some(parse_wordpress_advisory_catalog(catalogue.as_bytes()).unwrap()),
        );
        let result = evaluate_wordpress_review(&[], &inputs).unwrap();
        let core = result
            .advisories()
            .iter()
            .find(|evaluation| evaluation.record().id() == "SYNTHETIC-CORE-1")
            .unwrap();

        assert!(core.prerequisites().iter().any(|evaluation| {
            evaluation.outcome() == WordPressPrerequisiteOutcome::ContradictedOnSuppliedFacts
        }));
        assert!(core.prerequisites().iter().any(|evaluation| {
            evaluation.outcome() == WordPressPrerequisiteOutcome::Unsupported
        }));
        assert_eq!(
            core.applicability(),
            WordPressApplicability::ContradictedByDeclaredFacts
        );
    }

    #[test]
    fn absent_or_unknown_patch_assertions_do_not_mean_patch_absence() {
        let without_patch = CONTEXT.replace(
            r#""patches":[{"id":"vendor-backport-1","state":"applied"}]"#,
            r#""patches":[]"#,
        );
        let inputs = WordPressReviewInputs::new(
            Some(parse_wordpress_context(without_patch.as_bytes()).unwrap()),
            Some(parse_wordpress_advisory_catalog(CATALOG.as_bytes()).unwrap()),
        );
        let result = evaluate_wordpress_review(&[], &inputs).unwrap();
        let plugin = result
            .advisories()
            .iter()
            .find(|evaluation| evaluation.record().id() == "SYNTHETIC-PLUGIN-1")
            .unwrap();
        assert_eq!(
            plugin.prerequisites()[1].outcome(),
            WordPressPrerequisiteOutcome::Unknown
        );
        assert_eq!(
            plugin.applicability(),
            WordPressApplicability::IndeterminateMissingEvidence
        );
    }

    #[test]
    fn unsupported_and_missing_prerequisites_are_distinct() {
        let unsupported = CATALOG.replacen(
            "{\"kind\":\"hosting_os\",\"equals\":\"linux\"}",
            "{\"kind\":\"unsupported\",\"name\":\"php-extension-state\"}",
            1,
        );
        let inputs = WordPressReviewInputs::new(
            None,
            Some(parse_wordpress_advisory_catalog(unsupported.as_bytes()).unwrap()),
        );
        let result = evaluate_wordpress_review(&[], &inputs).unwrap();
        let unsupported = result.advisories()[0]
            .prerequisites()
            .iter()
            .find(|evaluation| {
                matches!(
                    evaluation.prerequisite(),
                    WordPressPrerequisite::Unsupported { .. }
                )
            })
            .unwrap();
        assert_eq!(
            unsupported.outcome(),
            WordPressPrerequisiteOutcome::Unsupported
        );
        let multisite = result.advisories()[0]
            .prerequisites()
            .iter()
            .find(|evaluation| {
                matches!(
                    evaluation.prerequisite(),
                    WordPressPrerequisite::Multisite { .. }
                )
            })
            .unwrap();
        assert_eq!(multisite.outcome(), WordPressPrerequisiteOutcome::Unknown);
        assert_eq!(
            result.advisories()[0].applicability(),
            WordPressApplicability::IndeterminateUnsupported
        );
    }

    #[test]
    fn absent_catalogue_is_visible_and_never_an_all_clear() {
        let result = evaluate_wordpress_review(
            &[WordPressComponentSignal::generator_metadata(None).unwrap()],
            &WordPressReviewInputs::default(),
        )
        .unwrap();
        assert_eq!(
            result.catalog_status(),
            WordPressCatalogStatus::CatalogNotSupplied
        );
        assert_eq!(result.catalog_metadata(), None);
        assert!(result.advisories().is_empty());
        assert_eq!(
            result.components()[0].evidence_class(),
            WordPressComponentEvidenceClass::ObservedHint
        );
    }

    #[test]
    fn no_matching_component_keeps_record_indeterminate() {
        let inputs = WordPressReviewInputs::new(
            None,
            Some(parse_wordpress_advisory_catalog(CATALOG.as_bytes()).unwrap()),
        );
        let result = evaluate_wordpress_review(&[], &inputs).unwrap();
        for advisory in result.advisories() {
            assert_eq!(
                advisory.component_evidence(),
                WordPressComponentEvidenceClass::Unknown
            );
            assert_eq!(
                advisory.version_relation(),
                WordPressVersionRelation::Unknown
            );
            assert!(matches!(
                advisory.applicability(),
                WordPressApplicability::IndeterminateMissingEvidence
                    | WordPressApplicability::IndeterminateUnsupported
            ));
        }
    }

    #[test]
    fn parser_is_order_independent_but_catalog_output_is_deterministic() {
        let reordered = CATALOG.replace(
            "\"schema\":\"security.wordpress-advisory-catalog/v1\",\n      \"catalog\"",
            "\"catalog\"",
        );
        let reordered = reordered.replacen(
            "\"records\":[",
            "\"schema\":\"security.wordpress-advisory-catalog/v1\",\"records\":[",
            1,
        );
        let parsed = parse_wordpress_advisory_catalog(reordered.as_bytes()).unwrap();
        assert_eq!(
            parsed,
            parse_wordpress_advisory_catalog(CATALOG.as_bytes()).unwrap()
        );
        assert_eq!(parsed.records()[0].id(), "SYNTHETIC-CORE-1");
        assert_eq!(parsed.records()[1].id(), "SYNTHETIC-PLUGIN-1");
    }

    #[test]
    fn schema_and_catalog_size_limits_fail_closed() {
        let wrong = CONTEXT.replace(WORDPRESS_CONTEXT_SCHEMA, "security.wordpress-context/v2");
        assert_eq!(
            parse_wordpress_context(wrong.as_bytes()),
            Err(WordPressReviewError::UnsupportedSchema)
        );
        assert_eq!(
            parse_wordpress_advisory_catalog(&vec![b' '; MAX_WORDPRESS_ADVISORY_CATALOG_BYTES + 1]),
            Err(WordPressReviewError::CatalogTooLarge)
        );
    }

    #[test]
    fn source_urls_and_inert_data_cannot_express_executable_policy() {
        for replacement in [
            "javascript:alert(1)",
            "http://example.test/advisory",
            "https://user:secret@example.test/advisory",
        ] {
            let document = CATALOG.replace("https://example.test/advisories/core-1", replacement);
            assert_eq!(
                parse_wordpress_advisory_catalog(document.as_bytes()),
                Err(WordPressReviewError::InvalidCatalog)
            );
        }
        let script = CATALOG.replacen(
            "\"summary\":\"Synthetic bounded core record\"",
            "\"summary\":\"Synthetic bounded core record\",\"script\":\"system('id')\"",
            1,
        );
        assert_eq!(
            parse_wordpress_advisory_catalog(script.as_bytes()),
            Err(WordPressReviewError::InvalidCatalog)
        );
    }

    #[test]
    fn signal_limit_and_invalid_asset_identities_fail_closed() {
        let signal = WordPressComponentSignal::generator_metadata(None).unwrap();
        assert_eq!(
            evaluate_wordpress_review(
                &vec![signal; MAX_WORDPRESS_SIGNALS + 1],
                &WordPressReviewInputs::default()
            ),
            Err(WordPressReviewError::SignalLimitExceeded)
        );
        assert!(WordPressComponentSignal::same_origin_asset(
            WordPressComponentKind::Plugin,
            "../escape"
        )
        .is_err());
        assert!(WordPressComponentSignal::same_origin_asset(
            WordPressComponentKind::Plugin,
            "wordpress"
        )
        .is_err());
    }

    #[test]
    fn disjoint_signal_and_context_component_bounds_form_one_valid_result() {
        let signals = (0..MAX_WORDPRESS_SIGNALS)
            .map(|index| {
                WordPressComponentSignal::same_origin_asset(
                    WordPressComponentKind::Plugin,
                    &format!("observed-{index:03}"),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let components = (0..MAX_WORDPRESS_CONTEXT_COMPONENTS)
            .map(|index| WordPressContextComponent {
                identity: WordPressComponentIdentity::new(
                    WordPressComponentKind::Plugin,
                    format!("declared-{index:03}"),
                )
                .unwrap(),
                version: None,
                activation: None,
                patches: Vec::new(),
                inventory_status: None,
            })
            .collect();
        let context = WordPressContext {
            root_url: Url::parse("https://example.test/").unwrap(),
            hosting_os: None,
            multisite: None,
            components,
        };

        let result =
            evaluate_wordpress_review(&signals, &WordPressReviewInputs::new(Some(context), None))
                .unwrap();

        assert_eq!(
            MAX_WORDPRESS_RESULT_COMPONENTS,
            MAX_WORDPRESS_SIGNALS + MAX_WORDPRESS_CONTEXT_COMPONENTS
        );
        assert_eq!(result.components().len(), MAX_WORDPRESS_RESULT_COMPONENTS);
    }

    #[test]
    fn combined_signal_and_context_versions_use_the_explicit_result_bound() {
        let signals = (0..MAX_WORDPRESS_SIGNALS)
            .map(|index| {
                WordPressComponentSignal::generator_metadata(Some(&format!("1.0.{index}"))).unwrap()
            })
            .collect::<Vec<_>>();
        let components = (0..MAX_WORDPRESS_CONTEXT_COMPONENTS)
            .map(|index| WordPressContextComponent {
                identity: WordPressComponentIdentity::new(
                    WordPressComponentKind::Plugin,
                    format!("declared-{index:03}"),
                )
                .unwrap(),
                version: Some(format!("2.0.{index}")),
                activation: None,
                patches: Vec::new(),
                inventory_status: None,
            })
            .collect();
        let context = WordPressContext {
            root_url: Url::parse("https://example.test/").unwrap(),
            hosting_os: None,
            multisite: None,
            components,
        };

        let result =
            evaluate_wordpress_review(&signals, &WordPressReviewInputs::new(Some(context), None))
                .unwrap();
        let version_rows = result
            .components()
            .iter()
            .map(|component| component.versions().len())
            .sum::<usize>();

        assert_eq!(
            MAX_WORDPRESS_RESULT_VERSION_EVIDENCE,
            MAX_WORDPRESS_SIGNALS + MAX_WORDPRESS_CONTEXT_COMPONENTS
        );
        assert_eq!(version_rows, MAX_WORDPRESS_RESULT_VERSION_EVIDENCE);
    }

    #[test]
    fn external_catalog_selects_only_exact_component_associations() {
        let import = parse_wordfence_v3_production(
            &include_bytes!(
                "../../../docs/examples/wordpress-review/wordfence-v3/production.synthetic.json"
            )[..],
        )
        .unwrap();
        let context = parse_wordpress_context(
            br#"{
              "schema":"security.wordpress-context/v1",
              "root":"https://example.test/",
              "components":[
                {"kind":"plugin","slug":"termivar-fixture-component","version":"1.0"}
              ]
            }"#,
        )
        .unwrap();
        let inputs = WordPressReviewInputs::new(Some(context), None)
            .with_wordfence_v3_catalog(import)
            .unwrap();

        let result = evaluate_wordpress_review(&[], &inputs).unwrap();
        let external = result.external_review().unwrap();

        assert_eq!(result.catalog_status(), WordPressCatalogStatus::Evaluated);
        assert_eq!(result.catalog_schema(), None);
        assert_eq!(result.catalog_metadata(), None);
        assert!(result.advisories().is_empty());
        assert_eq!(external.counts().parsed_records(), 2);
        assert_eq!(external.counts().software_associations(), 3);
        assert_eq!(external.counts().selected_associations(), 1);
        assert_eq!(external.counts().evaluable_associations(), 0);
        assert_eq!(external.counts().unsupported_associations(), 1);
        assert_eq!(external.counts().excluded_associations(), 2);
        assert_eq!(external.evaluations().len(), 1);
        assert_eq!(external.notices().len(), 1);
        let evaluation = &external.evaluations()[0];
        assert_eq!(
            evaluation.key().source_namespace(),
            WORDFENCE_V3_SOURCE_NAMESPACE
        );
        assert_eq!(
            evaluation.key().component().kind(),
            WordPressComponentKind::Plugin
        );
        assert_eq!(
            evaluation.key().component().slug(),
            "termivar-fixture-component"
        );
        assert_eq!(
            evaluation.version_relation(),
            WordPressExternalVersionRelation::SourceComparisonSemanticsUnresolved
        );
        assert_eq!(
            evaluation.applicability(),
            WordPressExternalApplicability::IndeterminateUnsupported
        );
        assert_eq!(
            evaluation.version_evidence_resolution().status(),
            WordPressExternalVersionEvidenceStatus::SingleDeclaration
        );
        assert_eq!(
            evaluation
                .version_evidence_resolution()
                .evidence_row_count(),
            1
        );
        assert_eq!(
            evaluation
                .version_evidence_resolution()
                .distinct_spelling_count(),
            1
        );
        assert_eq!(
            evaluation.exploit_execution(),
            WordPressExecutionStatus::NotPerformed
        );
        assert_eq!(
            evaluation.impact_validation(),
            WordPressExecutionStatus::NotPerformed
        );
    }

    #[test]
    fn external_version_evidence_resolution_is_evaluator_owned_and_comparator_neutral() {
        for (operator_version, expected_status, expected_distinct) in [
            (
                "1.0",
                WordPressExternalVersionEvidenceStatus::RepeatedExactDeclaration,
                1,
            ),
            (
                "1.0.0",
                WordPressExternalVersionEvidenceStatus::MultipleDistinctDeclarations,
                2,
            ),
        ] {
            let import = parse_wordfence_v3_production(
                &include_bytes!(
                    "../../../docs/examples/wordpress-review/wordfence-v3/production.synthetic.json"
                )[..],
            )
            .unwrap();
            let context = parse_wordpress_context(
                format!(
                    r#"{{
                      "schema":"security.wordpress-context/v1",
                      "root":"https://example.test/",
                      "components":[{{"kind":"core","slug":"wordpress","version":"{operator_version}"}}]
                    }}"#
                )
                .as_bytes(),
            )
            .unwrap();
            let signals = [WordPressComponentSignal::generator_metadata(Some("1.0")).unwrap()];
            let result = evaluate_wordpress_review(
                &signals,
                &WordPressReviewInputs::new(Some(context), None)
                    .with_wordfence_v3_catalog(import)
                    .unwrap(),
            )
            .unwrap();
            let core = result
                .external_review()
                .unwrap()
                .evaluations()
                .iter()
                .find(|evaluation| {
                    evaluation.key().component().kind() == WordPressComponentKind::Core
                })
                .unwrap();
            let resolution = core.version_evidence_resolution();
            assert_eq!(resolution.status(), expected_status);
            assert_eq!(resolution.evidence_row_count(), 2);
            assert_eq!(resolution.distinct_spelling_count(), expected_distinct);
            assert_eq!(
                core.version_relation(),
                WordPressExternalVersionRelation::SourceComparisonSemanticsUnresolved
            );
        }
    }

    #[test]
    fn external_catalog_no_match_retains_counts_without_unrelated_rows_or_rights() {
        let import = parse_wordfence_v3_production(
            &include_bytes!(
                "../../../docs/examples/wordpress-review/wordfence-v3/production.synthetic.json"
            )[..],
        )
        .unwrap();
        let result = evaluate_wordpress_review(
            &[],
            &WordPressReviewInputs::new(None, None)
                .with_wordfence_v3_catalog(import)
                .unwrap(),
        )
        .unwrap();
        let external = result.external_review().unwrap();
        assert!(result.components().is_empty());
        assert_eq!(external.counts().selected_associations(), 0);
        assert_eq!(external.counts().excluded_associations(), 3);
        assert!(external.evaluations().is_empty());
        assert!(external.notices().is_empty());
    }

    #[test]
    fn every_selected_external_row_stays_indeterminate_without_a_comparison_policy() {
        let import = parse_wordfence_v3_production(
            &include_bytes!(
                "../../../docs/examples/wordpress-review/wordfence-v3/production.synthetic.json"
            )[..],
        )
        .unwrap();
        let context = parse_wordpress_context(
            br#"{
              "schema":"security.wordpress-context/v1",
              "root":"https://example.test/",
              "components":[
                {"kind":"core","slug":"wordpress","version":"1.0"},
                {"kind":"plugin","slug":"termivar-fixture-component","version":"1.0.0"},
                {"kind":"theme","slug":"termivar-fixture-component","version":"2.0"}
              ]
            }"#,
        )
        .unwrap();
        let result = evaluate_wordpress_review(
            &[],
            &WordPressReviewInputs::new(Some(context), None)
                .with_wordfence_v3_catalog(import)
                .unwrap(),
        )
        .unwrap();
        let external = result.external_review().unwrap();
        assert_eq!(external.counts().selected_associations(), 3);
        assert_eq!(external.counts().evaluable_associations(), 0);
        assert_eq!(external.counts().unsupported_associations(), 3);
        assert!(external.evaluations().iter().all(|evaluation| {
            evaluation.version_relation()
                == WordPressExternalVersionRelation::SourceComparisonSemanticsUnresolved
                && evaluation.applicability()
                    == WordPressExternalApplicability::IndeterminateUnsupported
                && evaluation.exploit_execution() == WordPressExecutionStatus::NotPerformed
                && evaluation.impact_validation() == WordPressExecutionStatus::NotPerformed
        }));
    }

    #[test]
    fn native_and_external_advisory_inputs_are_mutually_exclusive() {
        let import = parse_wordfence_v3_production(
            &include_bytes!(
                "../../../docs/examples/wordpress-review/wordfence-v3/production.synthetic.json"
            )[..],
        )
        .unwrap();
        let native = parse_wordpress_advisory_catalog(CATALOG.as_bytes()).unwrap();
        assert_eq!(
            WordPressReviewInputs::new(None, Some(native)).with_wordfence_v3_catalog(import),
            Err(WordPressReviewError::ConflictingAdvisoryInputs)
        );
    }

    #[test]
    fn external_selected_associations_fail_instead_of_truncating() {
        let document = wordfence_associations(MAX_WORDPRESS_ADVISORY_RECORDS + 1);
        let import = parse_wordfence_v3_production(document.as_bytes()).unwrap();
        let context = parse_wordpress_context(
            br#"{
              "schema":"security.wordpress-context/v1",
              "root":"https://example.test/",
              "components":[{"kind":"plugin","slug":"selected-plugin","version":"1.0"}]
            }"#,
        )
        .unwrap();
        assert_eq!(
            evaluate_wordpress_review(
                &[],
                &WordPressReviewInputs::new(Some(context), None)
                    .with_wordfence_v3_catalog(import)
                    .unwrap()
            ),
            Err(WordPressReviewError::ResultLimitExceeded)
        );
    }
}
