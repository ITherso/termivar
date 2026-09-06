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

pub const WORDPRESS_CONTEXT_SCHEMA: &str = "security.wordpress-context/v1";
pub const WORDPRESS_ADVISORY_CATALOG_SCHEMA: &str = "security.wordpress-advisory-catalog/v1";
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
pub const MAX_WORDPRESS_VERSION_COMPONENTS: usize = 8;
pub const MAX_WORDPRESS_VERSION_BYTES: usize = 64;
pub const MAX_WORDPRESS_SLUG_BYTES: usize = 64;
pub const MAX_WORDPRESS_IDENTIFIER_BYTES: usize = 128;
pub const MAX_WORDPRESS_REFERENCE_BYTES: usize = 2_048;
pub const MAX_WORDPRESS_SUMMARY_BYTES: usize = 1_024;
pub const MAX_WORDPRESS_REMEDIATION_BYTES: usize = 2_048;
pub const MAX_WORDPRESS_EVALUATION_WORK: usize = MAX_WORDPRESS_ADVISORY_RECORDS
    * (MAX_WORDPRESS_RANGES_PER_ADVISORY + MAX_WORDPRESS_PREREQUISITES_PER_ADVISORY);

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NumericDottedVersion {
    components: Vec<u32>,
}

impl NumericDottedVersion {
    pub fn parse(value: &str) -> Result<Self, NumericDottedVersionError> {
        if value.is_empty() || value.len() > MAX_WORDPRESS_VERSION_BYTES {
            return Err(NumericDottedVersionError);
        }
        let mut components = Vec::new();
        for part in value.split('.') {
            if components.len() == MAX_WORDPRESS_VERSION_COMPONENTS
                || part.is_empty()
                || !part.bytes().all(|byte| byte.is_ascii_digit())
                || (part.len() > 1 && part.starts_with('0'))
            {
                return Err(NumericDottedVersionError);
            }
            let component = part
                .bytes()
                .try_fold(0_u32, |value, digit| {
                    value.checked_mul(10)?.checked_add(u32::from(digit - b'0'))
                })
                .ok_or(NumericDottedVersionError)?;
            components.push(component);
        }
        while components.len() > 1 && components.last() == Some(&0) {
            components.pop();
        }
        Ok(Self { components })
    }

    #[must_use]
    pub fn components(&self) -> &[u32] {
        &self.components
    }
}

impl Ord for NumericDottedVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        self.components.cmp(&other.components)
    }
}

impl PartialOrd for NumericDottedVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("unsupported numeric-dotted WordPress version")]
pub struct NumericDottedVersionError;

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
    metadata: WordPressCatalogMetadata,
    records: Vec<WordPressAdvisoryRecord>,
}

impl WordPressAdvisoryCatalog {
    #[must_use]
    pub const fn metadata(&self) -> &WordPressCatalogMetadata {
        &self.metadata
    }

    #[must_use]
    pub fn records(&self) -> &[WordPressAdvisoryRecord] {
        &self.records
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct WordPressReviewInputs {
    context: Option<WordPressContext>,
    catalog: Option<WordPressAdvisoryCatalog>,
}

impl WordPressReviewInputs {
    #[must_use]
    pub const fn new(
        context: Option<WordPressContext>,
        catalog: Option<WordPressAdvisoryCatalog>,
    ) -> Self {
        Self { context, catalog }
    }

    #[must_use]
    pub const fn context(&self) -> Option<&WordPressContext> {
        self.context.as_ref()
    }

    #[must_use]
    pub const fn catalog(&self) -> Option<&WordPressAdvisoryCatalog> {
        self.catalog.as_ref()
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WordPressAdvisoryEvaluation {
    record: WordPressAdvisoryRecord,
    component_evidence: WordPressComponentEvidenceClass,
    version_relation: WordPressVersionRelation,
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
    catalog_metadata: Option<WordPressCatalogMetadata>,
    components: Vec<WordPressComponentAssessment>,
    advisories: Vec<WordPressAdvisoryEvaluation>,
}

impl WordPressReviewResult {
    #[must_use]
    pub const fn catalog_status(&self) -> WordPressCatalogStatus {
        self.catalog_status
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
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum WordPressReviewError {
    #[error("WordPress context exceeds its byte limit")]
    ContextTooLarge,
    #[error("WordPress advisory catalog exceeds its byte limit")]
    CatalogTooLarge,
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
    #[error("WordPress advisory catalog is invalid")]
    InvalidCatalog,
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
    require_schema(&value, WORDPRESS_ADVISORY_CATALOG_SCHEMA)?;
    let wire: CatalogWire =
        serde_json::from_value(value).map_err(|_| WordPressReviewError::InvalidCatalog)?;
    validate_identifier(&wire.catalog.id)?;
    validate_identifier(&wire.catalog.revision)?;
    validate_date(&wire.catalog.retrieved_on)?;
    if wire.records.len() > MAX_WORDPRESS_ADVISORY_RECORDS {
        return Err(WordPressReviewError::InvalidCatalog);
    }
    let metadata = WordPressCatalogMetadata {
        id: wire.catalog.id,
        revision: wire.catalog.revision,
        retrieved_on: wire.catalog.retrieved_on,
    };
    let mut record_ids = BTreeSet::new();
    let mut records = Vec::with_capacity(wire.records.len());
    let mut work = 0_usize;
    for record in wire.records {
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
        let mut affected_ranges = record
            .affected_ranges
            .into_iter()
            .map(validate_range)
            .collect::<Result<Vec<_>, _>>()?;
        affected_ranges.sort();
        affected_ranges.dedup();
        let mut fixed_versions = Vec::with_capacity(record.fixed_versions.len());
        let mut fixed_seen = BTreeSet::new();
        for fixed in record.fixed_versions {
            let parsed = NumericDottedVersion::parse(&fixed)
                .map_err(|_| WordPressReviewError::InvalidVersionRange)?;
            if !fixed_seen.insert(parsed.clone()) {
                return Err(WordPressReviewError::InvalidCatalog);
            }
            fixed_versions.push((parsed, fixed));
        }
        fixed_versions.sort_by(|left, right| left.0.cmp(&right.0));
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
        records.push(WordPressAdvisoryRecord {
            id: record.id,
            component,
            source,
            cve: record.cve,
            summary: record.summary,
            affected_ranges,
            fixed_versions,
            prerequisites,
            remediation,
        });
    }
    records.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(WordPressAdvisoryCatalog { metadata, records })
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
    for (identity, aggregate) in &aggregates {
        components.push(component_assessment(identity.clone(), aggregate));
    }
    let Some(catalog) = inputs.catalog() else {
        return Ok(WordPressReviewResult {
            catalog_status: WordPressCatalogStatus::CatalogNotSupplied,
            catalog_metadata: None,
            components,
            advisories: Vec::new(),
        });
    };
    let work = catalog.records().iter().try_fold(0_usize, |work, record| {
        work.checked_add(record.affected_ranges.len())?
            .checked_add(record.prerequisites.len())
    });
    if work.is_none_or(|work| work > MAX_WORDPRESS_EVALUATION_WORK) {
        return Err(WordPressReviewError::EvaluationLimitExceeded);
    }
    let assessments = components
        .iter()
        .map(|assessment| (assessment.identity.clone(), assessment))
        .collect::<BTreeMap<_, _>>();
    let mut advisories = Vec::with_capacity(catalog.records().len());
    for record in catalog.records() {
        let assessment = assessments.get(record.component());
        let component_evidence = assessment
            .map_or(WordPressComponentEvidenceClass::Unknown, |assessment| {
                assessment.evidence_class
            });
        let version_relation = evaluate_version_relation(assessment.copied(), record);
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
            prerequisites,
            applicability,
        });
    }
    Ok(WordPressReviewResult {
        catalog_status: WordPressCatalogStatus::Evaluated,
        catalog_metadata: Some(catalog.metadata().clone()),
        components,
        advisories,
    })
}

#[derive(Default)]
struct ComponentAggregate {
    sources: BTreeSet<WordPressEvidenceSource>,
    confidence_classes: BTreeSet<WordPressEvidenceConfidence>,
    versions: BTreeSet<WordPressVersionEvidence>,
    activation: Option<WordPressActivationState>,
}

fn component_assessment(
    identity: WordPressComponentIdentity,
    aggregate: &ComponentAggregate,
) -> WordPressComponentAssessment {
    let conflicting = versions_conflict(&aggregate.versions);
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
struct CatalogWire {
    #[allow(dead_code)]
    schema: String,
    catalog: CatalogMetadataWire,
    records: Vec<AdvisoryRecordWire>,
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
struct AdvisoryRecordWire {
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
}
