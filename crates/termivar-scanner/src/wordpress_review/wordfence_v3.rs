//! Bounded, transport-free decoding of a caller-supplied Wordfence V3
//! Production-format vulnerability export.
//!
//! Parsing establishes only the structure and exact bytes of a local export.
//! It does not authenticate its producer, establish feed completeness, select
//! an installed target, or choose version-comparison semantics.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    io::{BufReader, ErrorKind, Read},
    mem::size_of,
};

use serde::{
    de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor},
    Deserialize,
};
use serde_json::{Number, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;

use super::{WordPressComponentIdentity, WordPressComponentKind};

pub const WORDFENCE_V3_SOURCE_NAMESPACE: &str = "wordfence-intelligence";
pub const WORDFENCE_V3_PRODUCTION_FORMAT: &str = "wordfence-v3-production";
pub const WORDFENCE_V3_MAPPING_REVISION: &str = "termivar-wordfence-v3-production/v1";
pub const WORDFENCE_V3_MAPPING_REVISION_V2: &str = "termivar-wordfence-v3-production/v2";
pub const WORDFENCE_V3_IDENTITY_MAPPING_POLICY: &str =
    "termivar.wordfence-v3-exact-plus-ascii-lowercase-candidate/v1";
pub const WORDFENCE_V3_RESOURCE_POLICY_V1: &str = "termivar.wordfence-v3-bounded-capacity/v1";
pub const WORDFENCE_V3_RESOURCE_POLICY_V2: &str = "termivar.wordfence-v3-bounded-capacity/v2";
pub const WORDFENCE_V3_RESOURCE_POLICY_V3: &str = "termivar.wordfence-v3-bounded-capacity/v3";
pub const MAX_WORDFENCE_V3_PRODUCTION_BYTES: usize = 256 * 1024 * 1024;
pub const MAX_WORDFENCE_V3_RECORDS: usize = 100_000;
pub const MAX_WORDFENCE_V3_SOFTWARE_ASSOCIATIONS: usize = 200_000;
pub const MAX_WORDFENCE_V3_RECORD_BYTES: usize = 768 * 1024;
pub const MAX_WORDFENCE_V3_RETAINED_BYTES: usize = 160 * 1024 * 1024;
pub const MAX_WORDFENCE_V3_RANGES_PER_ASSOCIATION: usize = 128;
pub const MAX_WORDFENCE_V3_PATCHED_VERSIONS: usize = 128;
pub const MAX_WORDFENCE_V3_REFERENCES: usize = 64;
pub const MAX_WORDFENCE_V3_RESEARCHERS: usize = 64;
// One message plus at most fifteen attribution entries is the supported
// Production-format notice projection.
pub const MAX_WORDFENCE_V3_NOTICE_PARTIES: usize = 15;
pub(crate) const MAX_WORDFENCE_V3_SOFTWARE_PER_RECORD: usize = 2_048;
const MAX_WORDFENCE_V3_JSON_NODES_PER_RECORD: usize = 32_768;
const MAX_WORDFENCE_V3_ARRAY_ITEMS_PER_RECORD: usize = 4_096;
// These are external-import decoder limits. A supported affected_versions map
// may contain 128 range labels and each label may contain 256 UTF-8 bytes; the
// stricter native Termivar catalogue decoder retains its existing limits.
const MAX_WORDFENCE_V3_OBJECT_MEMBERS_PER_RECORD: usize = 128;
const MAX_WORDFENCE_V3_JSON_DEPTH: usize = 10;
const MAX_WORDFENCE_V3_JSON_KEY_BYTES: usize = 256;
const MAX_WORDFENCE_V3_JSON_STRING_BYTES: usize = 4_096;
const WORDFENCE_DUPLICATE_KEY_MARKER: &str = "termivar_wordfence_duplicate_key";
const WORDFENCE_JSON_LIMIT_MARKER: &str = "termivar_wordfence_json_limit";
// Rust's BTree implementation does not expose node allocation sizes. Charge a
// conservative per-logical-entry allowance in addition to stored key/value
// sizes so the public retained-data budget never treats nodes as free.
const CONSERVATIVE_BTREE_NODE_BYTES_PER_ENTRY: usize = 64;
const MAX_WORDFENCE_V3_TITLE_BYTES: usize = 1_024;
const MAX_WORDFENCE_V3_DESCRIPTION_BYTES: usize = 4_096;
const MAX_WORDFENCE_V3_REMEDIATION_BYTES: usize = 2_048;
const MAX_WORDFENCE_V3_NOTICE_TEXT_BYTES: usize = 2_048;
const MAX_WORDFENCE_V3_NAME_BYTES: usize = 1_024;
const MAX_WORDFENCE_V3_REFERENCE_BYTES: usize = 2_048;
const MAX_WORDFENCE_V3_VERSION_BYTES: usize = 64;
const MAX_WORDFENCE_V3_RANGE_LABEL_BYTES: usize = 256;
pub const MAX_WORDFENCE_V3_RESEARCHER_BYTES: usize = 512;
const MAX_WORDFENCE_V3_CVE_BYTES: usize = 32;
const MAX_WORDFENCE_V3_CVSS_VECTOR_BYTES: usize = 256;
const MAX_WORDFENCE_V3_SOURCE_SLUG_BYTES: usize = 128;
const MAX_WORDFENCE_V3_RECORD_BYTES_V1: usize = 512 * 1024;
const MAX_WORDFENCE_V3_RETAINED_BYTES_V1: usize = 64 * 1024 * 1024;
const MAX_WORDFENCE_V3_RETAINED_BYTES_V2: usize = 128 * 1024 * 1024;
const MAX_WORDFENCE_V3_DESCRIPTION_BYTES_V1: usize = 2_048;
const MAX_WORDFENCE_V3_COLLECTION_ITEMS_V1: usize = 64;

type AssociationCoordinate = (usize, usize);
type ComponentAssociationIndex = BTreeMap<WordPressComponentIdentity, Vec<AssociationCoordinate>>;

#[derive(Debug, Error, Clone, Copy, Eq, PartialEq)]
pub enum WordfenceV3ProductionError {
    #[error("Wordfence Production input could not be read")]
    ReadFailed,
    #[error("Wordfence Production input is empty")]
    EmptyInput,
    #[error("Wordfence Production input exceeds its byte limit")]
    InputTooLarge,
    #[error("a Wordfence Production record exceeds its byte limit")]
    RecordTooLarge,
    #[error("Wordfence Production input is malformed JSON")]
    MalformedJson,
    #[error("Wordfence Production input contains a duplicate object key")]
    DuplicateKey,
    #[error("Wordfence Production input exceeds a structural limit")]
    StructuralLimitExceeded,
    #[error("Wordfence Production input contains an unsupported field or value")]
    UnsupportedValue,
    #[error("Wordfence Production input contains a conflicting identity")]
    ConflictingIdentity,
    #[error("Wordfence Production retained data exceeds its memory limit")]
    RetainedDataTooLarge,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WordfenceV3ProductionImport {
    byte_length: u64,
    sha256: [u8; 32],
    semantic_sha256: [u8; 32],
    retained_bytes: usize,
    software_association_count: usize,
    affected_range_count: usize,
    identity_counts: WordfenceV3IdentityCounts,
    resource_policy: &'static str,
    records: Vec<WordfenceV3Record>,
    notices: Vec<WordfenceV3Notice>,
    component_index: ComponentAssociationIndex,
}

pub type WordfenceV3Catalog = WordfenceV3ProductionImport;

impl WordfenceV3ProductionImport {
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
    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    #[must_use]
    pub const fn software_association_count(&self) -> usize {
        self.software_association_count
    }

    #[must_use]
    pub const fn affected_range_count(&self) -> usize {
        self.affected_range_count
    }

    #[must_use]
    pub const fn identity_counts(&self) -> &WordfenceV3IdentityCounts {
        &self.identity_counts
    }

    #[must_use]
    pub const fn mapping_revision(&self) -> &'static str {
        if self.identity_counts.requires_source_identity_mapping() {
            WORDFENCE_V3_MAPPING_REVISION_V2
        } else {
            WORDFENCE_V3_MAPPING_REVISION
        }
    }

    #[must_use]
    pub const fn resource_policy(&self) -> &'static str {
        self.resource_policy
    }

    #[must_use]
    pub fn records(&self) -> &[WordfenceV3Record] {
        &self.records
    }

    #[must_use]
    pub fn notices(&self) -> &[WordfenceV3Notice] {
        &self.notices
    }

    pub fn associations_for<'a>(
        &'a self,
        component: &'a WordPressComponentIdentity,
    ) -> impl Iterator<Item = WordfenceV3AssociationView<'a>> + 'a {
        self.component_index
            .get(component)
            .into_iter()
            .flat_map(move |coordinates| {
                coordinates
                    .iter()
                    .map(move |&(record_index, association_index)| {
                        let record = &self.records[record_index];
                        WordfenceV3AssociationView {
                            record,
                            association: &record.software[association_index],
                        }
                    })
            })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WordfenceV3Record {
    upstream_id: String,
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
    software: Vec<WordfenceV3SoftwareAssociation>,
    unresolved_software: Vec<WordfenceV3UnresolvedSoftwareAssociation>,
}

impl WordfenceV3Record {
    #[must_use]
    pub fn upstream_id(&self) -> &str {
        &self.upstream_id
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
    pub fn software(&self) -> &[WordfenceV3SoftwareAssociation] {
        &self.software
    }

    #[must_use]
    pub fn unresolved_software(&self) -> &[WordfenceV3UnresolvedSoftwareAssociation] {
        &self.unresolved_software
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum WordfenceV3IdentityMapping {
    Exact,
    AsciiCaseFoldCandidate,
    AsciiCaseFoldAmbiguous,
}

impl WordfenceV3IdentityMapping {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::AsciiCaseFoldCandidate => "ascii_case_fold_candidate",
            Self::AsciiCaseFoldAmbiguous => "ascii_case_fold_ambiguous",
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct WordfenceV3SourceComponentIdentity {
    kind: WordPressComponentKind,
    slug: String,
}

impl WordfenceV3SourceComponentIdentity {
    #[must_use]
    pub const fn kind(&self) -> WordPressComponentKind {
        self.kind
    }

    #[must_use]
    pub fn slug(&self) -> &str {
        &self.slug
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct WordfenceV3IdentityCounts {
    exact: usize,
    candidate: usize,
    ambiguous: usize,
    unresolved: usize,
}

impl WordfenceV3IdentityCounts {
    #[must_use]
    pub const fn exact(&self) -> usize {
        self.exact
    }

    #[must_use]
    pub const fn candidate(&self) -> usize {
        self.candidate
    }

    #[must_use]
    pub const fn ambiguous(&self) -> usize {
        self.ambiguous
    }

    #[must_use]
    pub const fn unresolved(&self) -> usize {
        self.unresolved
    }

    const fn requires_source_identity_mapping(&self) -> bool {
        self.candidate != 0 || self.ambiguous != 0 || self.unresolved != 0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WordfenceV3SoftwareAssociation {
    key: WordfenceV3AssociationKey,
    identity_mapping: WordfenceV3IdentityMapping,
    identity_collision_raw_count: Option<usize>,
    display_name: String,
    affected_ranges: Vec<WordfenceV3AffectedRange>,
    patched: bool,
    patched_versions: Vec<String>,
    remediation: String,
}

impl WordfenceV3SoftwareAssociation {
    #[must_use]
    pub const fn key(&self) -> &WordfenceV3AssociationKey {
        &self.key
    }
    #[must_use]
    pub const fn component(&self) -> &WordPressComponentIdentity {
        &self.key.component
    }
    #[must_use]
    pub const fn source_component(&self) -> &WordfenceV3SourceComponentIdentity {
        &self.key.source_component
    }
    #[must_use]
    pub const fn identity_mapping(&self) -> WordfenceV3IdentityMapping {
        self.identity_mapping
    }
    #[must_use]
    pub const fn identity_collision_raw_count(&self) -> Option<usize> {
        self.identity_collision_raw_count
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
    pub const fn patched(&self) -> bool {
        self.patched
    }
    #[must_use]
    pub fn patched_versions(&self) -> &[String] {
        &self.patched_versions
    }
    #[must_use]
    pub fn remediation(&self) -> &str {
        &self.remediation
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WordfenceV3UnresolvedSoftwareAssociation {
    upstream_id: String,
    source_component: WordfenceV3SourceComponentIdentity,
    source_association_sha256: [u8; 32],
    display_name: String,
    affected_ranges: Vec<WordfenceV3AffectedRange>,
    patched: bool,
    patched_versions: Vec<String>,
    remediation: String,
}

impl WordfenceV3UnresolvedSoftwareAssociation {
    #[must_use]
    pub fn upstream_id(&self) -> &str {
        &self.upstream_id
    }

    #[must_use]
    pub const fn source_component(&self) -> &WordfenceV3SourceComponentIdentity {
        &self.source_component
    }

    #[must_use]
    pub const fn source_association_sha256(&self) -> &[u8; 32] {
        &self.source_association_sha256
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
    pub const fn patched(&self) -> bool {
        self.patched
    }

    #[must_use]
    pub fn patched_versions(&self) -> &[String] {
        &self.patched_versions
    }

    #[must_use]
    pub fn remediation(&self) -> &str {
        &self.remediation
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct WordfenceV3AssociationKey {
    upstream_id: String,
    component: WordPressComponentIdentity,
    source_component: WordfenceV3SourceComponentIdentity,
    source_association_sha256: [u8; 32],
}

impl WordfenceV3AssociationKey {
    #[must_use]
    pub const fn source_namespace(&self) -> &'static str {
        WORDFENCE_V3_SOURCE_NAMESPACE
    }
    #[must_use]
    pub fn upstream_id(&self) -> &str {
        &self.upstream_id
    }
    #[must_use]
    pub const fn component(&self) -> &WordPressComponentIdentity {
        &self.component
    }

    #[must_use]
    pub const fn source_component(&self) -> &WordfenceV3SourceComponentIdentity {
        &self.source_component
    }

    #[must_use]
    pub const fn source_association_sha256(&self) -> &[u8; 32] {
        &self.source_association_sha256
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct WordfenceV3AffectedRange {
    label: String,
    from: WordfenceV3RangeEndpoint,
    to: WordfenceV3RangeEndpoint,
}

impl WordfenceV3AffectedRange {
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }
    #[must_use]
    pub const fn from(&self) -> &WordfenceV3RangeEndpoint {
        &self.from
    }
    #[must_use]
    pub const fn to(&self) -> &WordfenceV3RangeEndpoint {
        &self.to
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct WordfenceV3RangeEndpoint {
    value: WordfenceV3RangeValue,
    inclusive: bool,
}

impl WordfenceV3RangeEndpoint {
    #[must_use]
    pub const fn value(&self) -> &WordfenceV3RangeValue {
        &self.value
    }
    #[must_use]
    pub const fn inclusive(&self) -> bool {
        self.inclusive
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum WordfenceV3RangeValue {
    Any,
    Declared(String),
}

impl WordfenceV3RangeValue {
    #[must_use]
    pub fn declared(&self) -> &str {
        match self {
            Self::Any => "*",
            Self::Declared(value) => value,
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct WordfenceV3Cwe {
    id: u32,
    name: String,
    description: String,
}

impl WordfenceV3Cwe {
    #[must_use]
    pub const fn id(&self) -> u32 {
        self.id
    }
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
    #[must_use]
    pub fn description(&self) -> &str {
        &self.description
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct WordfenceV3Cvss {
    vector: String,
    score: String,
    rating: WordfenceV3CvssRating,
}

impl WordfenceV3Cvss {
    #[must_use]
    pub fn vector(&self) -> &str {
        &self.vector
    }
    #[must_use]
    pub fn score(&self) -> &str {
        &self.score
    }
    #[must_use]
    pub const fn rating(&self) -> WordfenceV3CvssRating {
        self.rating
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum WordfenceV3CvssRating {
    None,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct WordfenceV3Notice {
    id: String,
    message: String,
    party: String,
    notice: String,
    license: String,
    license_url: String,
}

impl WordfenceV3Notice {
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
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
    pub fn license_url(&self) -> &str {
        &self.license_url
    }
}

#[derive(Clone, Copy)]
pub struct WordfenceV3AssociationView<'a> {
    record: &'a WordfenceV3Record,
    association: &'a WordfenceV3SoftwareAssociation,
}

impl<'a> WordfenceV3AssociationView<'a> {
    #[must_use]
    pub const fn record(self) -> &'a WordfenceV3Record {
        self.record
    }
    #[must_use]
    pub const fn association(self) -> &'a WordfenceV3SoftwareAssociation {
        self.association
    }
    #[must_use]
    pub fn upstream_id(self) -> &'a str {
        self.record.upstream_id()
    }
    #[must_use]
    pub const fn component(self) -> &'a WordPressComponentIdentity {
        self.association.component()
    }
}

/// Parses one complete, bounded Production-format export from a caller-owned
/// reader. The root map is consumed incrementally and only one bounded raw
/// record plus its decoded value is live during conversion.
pub fn parse_wordfence_v3_production<R: Read>(
    reader: R,
) -> Result<WordfenceV3ProductionImport, WordfenceV3ProductionError> {
    parse_wordfence_v3_production_with_limits(
        reader,
        MAX_WORDFENCE_V3_PRODUCTION_BYTES,
        MAX_WORDFENCE_V3_RETAINED_BYTES,
    )
}

fn parse_wordfence_v3_production_with_limits<R: Read>(
    reader: R,
    maximum_input_bytes: usize,
    maximum_retained_bytes: usize,
) -> Result<WordfenceV3ProductionImport, WordfenceV3ProductionError> {
    let mut cursor = MeasuredCursor::with_limit(reader, maximum_input_bytes);
    let mut retained_during_parse = RetainedBudget::with_base(
        maximum_retained_bytes,
        size_of::<WordfenceV3ProductionImport>(),
    )?;
    let first = cursor.next_non_whitespace()?;
    if first.is_none() && cursor.byte_length == 0 {
        return Err(WordfenceV3ProductionError::EmptyInput);
    }
    if first != Some(b'{') {
        return Err(WordfenceV3ProductionError::MalformedJson);
    }

    let mut upstream_ids = BTreeSet::new();
    let mut records = Vec::new();
    let mut notices = BTreeMap::<String, WordfenceV3Notice>::new();
    let mut software_association_count = 0_usize;
    let mut affected_range_count = 0_usize;
    let mut requires_resource_policy_v2 = false;
    let mut requires_semantic_digest_v2 = false;
    let mut delimiter = cursor.next_non_whitespace()?;
    if delimiter != Some(b'}') {
        loop {
            if delimiter != Some(b'"') {
                return Err(WordfenceV3ProductionError::MalformedJson);
            }
            if records.len() == MAX_WORDFENCE_V3_RECORDS {
                return Err(WordfenceV3ProductionError::StructuralLimitExceeded);
            }
            let upstream_id = cursor.capture_string()?;
            validate_uuid(&upstream_id)?;
            if upstream_ids.contains(&upstream_id) {
                return Err(WordfenceV3ProductionError::DuplicateKey);
            }
            retained_during_parse.add_btree_entry(
                size_of::<String>()
                    .checked_add(upstream_id.capacity())
                    .ok_or(WordfenceV3ProductionError::RetainedDataTooLarge)?,
            )?;
            upstream_ids.insert(upstream_id.clone());
            if cursor.next_non_whitespace()? != Some(b':') {
                return Err(WordfenceV3ProductionError::MalformedJson);
            }
            if cursor.next_non_whitespace()? != Some(b'{') {
                return Err(WordfenceV3ProductionError::UnsupportedValue);
            }
            let record_bytes = cursor.capture_record_object()?;
            let value = decode_bounded_record(&record_bytes)?;
            let (record, record_notices) = decode_record(upstream_id, value)?;
            requires_resource_policy_v2 |=
                record_requires_resource_policy_v2(record_bytes.len(), &record);
            requires_semantic_digest_v2 |= record_requires_semantic_digest_v2(&record);
            for notice in record_notices {
                let id = notice.id.clone();
                if let Some(existing) = notices.get(&id) {
                    if existing != &notice {
                        return Err(WordfenceV3ProductionError::ConflictingIdentity);
                    }
                } else {
                    retained_during_parse.add_notice_map_entry(&id, &notice)?;
                    notices.insert(id, notice);
                }
            }
            let record_associations = record
                .software
                .len()
                .checked_add(record.unresolved_software.len())
                .ok_or(WordfenceV3ProductionError::StructuralLimitExceeded)?;
            software_association_count = software_association_count
                .checked_add(record_associations)
                .ok_or(WordfenceV3ProductionError::StructuralLimitExceeded)?;
            if software_association_count > MAX_WORDFENCE_V3_SOFTWARE_ASSOCIATIONS {
                return Err(WordfenceV3ProductionError::StructuralLimitExceeded);
            }
            let ranges = record
                .software
                .iter()
                .map(WordfenceV3SoftwareAssociation::affected_ranges)
                .chain(
                    record
                        .unresolved_software
                        .iter()
                        .map(WordfenceV3UnresolvedSoftwareAssociation::affected_ranges),
                )
                .try_fold(0_usize, |count, ranges| count.checked_add(ranges.len()))
                .ok_or(WordfenceV3ProductionError::StructuralLimitExceeded)?;
            affected_range_count = affected_range_count
                .checked_add(ranges)
                .ok_or(WordfenceV3ProductionError::StructuralLimitExceeded)?;
            retained_during_parse.add(record_dynamic_bytes(&record)?)?;
            reserve_one_with_retained_accounting(&mut records, &mut retained_during_parse)?;
            records.push(record);

            delimiter = cursor.next_non_whitespace()?;
            match delimiter {
                Some(b',') => {
                    delimiter = cursor.next_non_whitespace()?;
                    if delimiter == Some(b'}') {
                        return Err(WordfenceV3ProductionError::MalformedJson);
                    }
                },
                Some(b'}') => break,
                _ => return Err(WordfenceV3ProductionError::MalformedJson),
            }
        }
    }
    if cursor.next_non_whitespace()?.is_some() {
        return Err(WordfenceV3ProductionError::MalformedJson);
    }
    let (byte_length, sha256) = cursor.finish();
    // Root-key duplicate detection is complete. Release that temporary tree
    // before constructing the final notice vector and component index so the
    // retained-data model does not rely on an optimizer shortening its scope.
    drop(upstream_ids);

    let (identity_counts, identity_resolution_peak) = resolve_identity_mappings(
        &mut records,
        retained_during_parse.total(),
        maximum_retained_bytes,
    )?;
    records.sort_by(|left, right| left.upstream_id.cmp(&right.upstream_id));
    let mut notice_values = Vec::new();
    reserve_exact_capacity_with_retained_accounting(
        &mut notice_values,
        notices.len(),
        &mut retained_during_parse,
    )?;
    notice_values.extend(notices.into_values());
    let parse_peak_bytes = retained_during_parse.total().max(identity_resolution_peak);
    // The notice map was consumed above, so its nodes and separately allocated
    // keys are no longer live. Final-form accounting below starts fresh rather
    // than carrying the conservative parse-peak counter forward.
    let base_retained = retained_records_and_notices_bytes(
        &records,
        records.capacity(),
        &notice_values,
        notice_values.capacity(),
        maximum_retained_bytes,
    )?;
    let (component_index, retained_bytes) =
        build_component_index(&records, base_retained, maximum_retained_bytes)?;
    let independently_measured = retained_import_bytes(
        &records,
        records.capacity(),
        &notice_values,
        notice_values.capacity(),
        &component_index,
        maximum_retained_bytes,
    )?;
    if retained_bytes != independently_measured {
        return Err(WordfenceV3ProductionError::RetainedDataTooLarge);
    }
    // The policy records the bounded import envelope the parser actually
    // needed, not only the size of the returned index. This prevents a
    // temporary root-key/collision phase that crossed an older ceiling from
    // being mislabeled as having fit that historical policy.
    let resource_policy = resource_policy_for_import(
        requires_resource_policy_v2,
        parse_peak_bytes,
        retained_bytes,
    );
    let semantic_sha256 = semantic_digest(
        &records,
        &notice_values,
        &identity_counts,
        requires_semantic_digest_v2,
    );
    Ok(WordfenceV3ProductionImport {
        byte_length,
        sha256,
        semantic_sha256,
        retained_bytes,
        software_association_count,
        affected_range_count,
        identity_counts,
        resource_policy,
        records,
        notices: notice_values,
        component_index,
    })
}

fn resource_policy_for_import(
    requires_expanded_record_semantics: bool,
    parse_peak_bytes: usize,
    retained_bytes: usize,
) -> &'static str {
    let import_envelope_bytes = retained_bytes.max(parse_peak_bytes);
    if import_envelope_bytes > MAX_WORDFENCE_V3_RETAINED_BYTES_V2 {
        WORDFENCE_V3_RESOURCE_POLICY_V3
    } else if requires_expanded_record_semantics
        || import_envelope_bytes > MAX_WORDFENCE_V3_RETAINED_BYTES_V1
    {
        WORDFENCE_V3_RESOURCE_POLICY_V2
    } else {
        WORDFENCE_V3_RESOURCE_POLICY_V1
    }
}

fn resolve_identity_mappings(
    records: &mut [WordfenceV3Record],
    retained_base: usize,
    maximum_retained: usize,
) -> Result<(WordfenceV3IdentityCounts, usize), WordfenceV3ProductionError> {
    // Collision discovery is a bounded parse-time allocation, not part of the
    // returned index. Keep it flat so a distinct singleton tree allocation is
    // not hidden behind every candidate key. The owned pair capacity and both
    // cloned strings are charged before they are allocated.
    let mut collision_budget = RetainedBudget::with_base(maximum_retained, retained_base)?;
    let mut spellings = Vec::<(
        WordPressComponentIdentity,
        WordfenceV3SourceComponentIdentity,
    )>::new();
    // Exact-only keys cannot produce a case-fold collision, so avoid cloning
    // every source identity in a large ordinary feed. Seed only keys that have
    // a candidate spelling, then add exact spellings for those same keys.
    for association in records
        .iter()
        .flat_map(|record| &record.software)
        .filter(|association| {
            association.identity_mapping == WordfenceV3IdentityMapping::AsciiCaseFoldCandidate
        })
    {
        push_identity_collision_pair(&mut spellings, association, &mut collision_budget)?;
    }
    spellings.sort();
    spellings.dedup();
    let candidate_spelling_count = spellings.len();
    for association in records
        .iter()
        .flat_map(|record| &record.software)
        .filter(|association| association.identity_mapping == WordfenceV3IdentityMapping::Exact)
    {
        if spellings[..candidate_spelling_count]
            .binary_search_by(|(component, _)| component.cmp(association.component()))
            .is_err()
        {
            continue;
        }
        push_identity_collision_pair(&mut spellings, association, &mut collision_budget)?;
    }
    spellings.sort();
    spellings.dedup();

    let mut counts = WordfenceV3IdentityCounts::default();
    for record in records.iter_mut() {
        counts.unresolved = counts
            .unresolved
            .checked_add(record.unresolved_software.len())
            .ok_or(WordfenceV3ProductionError::StructuralLimitExceeded)?;
        for association in &mut record.software {
            if association.identity_mapping == WordfenceV3IdentityMapping::AsciiCaseFoldCandidate {
                let distinct_source_identities =
                    identity_collision_count(&spellings, association.component());
                if distinct_source_identities > 1 {
                    association.identity_mapping =
                        WordfenceV3IdentityMapping::AsciiCaseFoldAmbiguous;
                    association.identity_collision_raw_count = Some(distinct_source_identities);
                }
            }
            let count = match association.identity_mapping {
                WordfenceV3IdentityMapping::Exact => &mut counts.exact,
                WordfenceV3IdentityMapping::AsciiCaseFoldCandidate => &mut counts.candidate,
                WordfenceV3IdentityMapping::AsciiCaseFoldAmbiguous => &mut counts.ambiguous,
            };
            *count = count
                .checked_add(1)
                .ok_or(WordfenceV3ProductionError::StructuralLimitExceeded)?;
        }
    }
    Ok((counts, collision_budget.total()))
}

fn push_identity_collision_pair(
    spellings: &mut Vec<(
        WordPressComponentIdentity,
        WordfenceV3SourceComponentIdentity,
    )>,
    association: &WordfenceV3SoftwareAssociation,
    retained: &mut RetainedBudget,
) -> Result<(), WordfenceV3ProductionError> {
    retained.add(
        association
            .component()
            .slug
            .capacity()
            .checked_add(association.source_component().slug.capacity())
            .ok_or(WordfenceV3ProductionError::RetainedDataTooLarge)?,
    )?;
    reserve_one_with_retained_accounting(spellings, retained)?;
    spellings.push((
        association.component().clone(),
        association.source_component().clone(),
    ));
    Ok(())
}

fn identity_collision_count(
    spellings: &[(
        WordPressComponentIdentity,
        WordfenceV3SourceComponentIdentity,
    )],
    component: &WordPressComponentIdentity,
) -> usize {
    let start = spellings.partition_point(|(candidate, _)| candidate < component);
    let end = spellings.partition_point(|(candidate, _)| candidate <= component);
    end.saturating_sub(start)
}

fn record_requires_resource_policy_v2(record_bytes: usize, record: &WordfenceV3Record) -> bool {
    record_bytes > MAX_WORDFENCE_V3_RECORD_BYTES_V1 || record_requires_semantic_digest_v2(record)
}

fn record_requires_semantic_digest_v2(record: &WordfenceV3Record) -> bool {
    record.description.len() > MAX_WORDFENCE_V3_DESCRIPTION_BYTES_V1
        || record_has_source_association_variants(record)
        || record.researchers.windows(2).any(|pair| pair[0] == pair[1])
        || record
            .cwe
            .as_ref()
            .is_some_and(|cwe| cwe.description.len() > MAX_WORDFENCE_V3_DESCRIPTION_BYTES_V1)
        || record
            .software
            .iter()
            .any(mapped_association_requires_resource_policy_v2)
        || record
            .unresolved_software
            .iter()
            .any(unresolved_association_requires_resource_policy_v2)
}

fn record_has_source_association_variants(record: &WordfenceV3Record) -> bool {
    record.software.windows(2).any(|pair| {
        pair[0].key.upstream_id == pair[1].key.upstream_id
            && pair[0].source_component() == pair[1].source_component()
    }) || record.unresolved_software.windows(2).any(|pair| {
        pair[0].upstream_id == pair[1].upstream_id
            && pair[0].source_component == pair[1].source_component
    })
}

fn mapped_association_requires_resource_policy_v2(
    association: &WordfenceV3SoftwareAssociation,
) -> bool {
    association.affected_ranges.len() > MAX_WORDFENCE_V3_COLLECTION_ITEMS_V1
        || association.patched_versions.len() > MAX_WORDFENCE_V3_COLLECTION_ITEMS_V1
        || source_versions_require_expanded_semantics(
            &association.affected_ranges,
            &association.patched_versions,
        )
}

fn unresolved_association_requires_resource_policy_v2(
    association: &WordfenceV3UnresolvedSoftwareAssociation,
) -> bool {
    association.affected_ranges.len() > MAX_WORDFENCE_V3_COLLECTION_ITEMS_V1
        || association.patched_versions.len() > MAX_WORDFENCE_V3_COLLECTION_ITEMS_V1
        || source_versions_require_expanded_semantics(
            &association.affected_ranges,
            &association.patched_versions,
        )
}

fn source_versions_require_expanded_semantics(
    ranges: &[WordfenceV3AffectedRange],
    patched_versions: &[String],
) -> bool {
    ranges.iter().any(|range| {
        [&range.from.value, &range.to.value]
            .into_iter()
            .any(|endpoint| match endpoint {
                WordfenceV3RangeValue::Any => false,
                WordfenceV3RangeValue::Declared(value) => source_version_requires_v2(value),
            })
    }) || patched_versions
        .iter()
        .any(|version| source_version_requires_v2(version))
}

fn source_version_requires_v2(value: &str) -> bool {
    !value.is_ascii() || value.chars().any(char::is_whitespace)
}

fn build_component_index(
    records: &[WordfenceV3Record],
    base_retained: usize,
    maximum_retained: usize,
) -> Result<(ComponentAssociationIndex, usize), WordfenceV3ProductionError> {
    use std::collections::btree_map::Entry;

    let mut retained = RetainedBudget::with_base(maximum_retained, base_retained)?;
    let mut index = ComponentAssociationIndex::new();
    for (record_index, record) in records.iter().enumerate() {
        for (association_index, association) in record.software.iter().enumerate() {
            let coordinates = match index.entry(association.component().clone()) {
                Entry::Vacant(entry) => {
                    retained.add_btree_entry(
                        size_of::<WordPressComponentIdentity>()
                            .checked_add(size_of::<Vec<AssociationCoordinate>>())
                            .and_then(|bytes| bytes.checked_add(entry.key().slug.capacity()))
                            .ok_or(WordfenceV3ProductionError::RetainedDataTooLarge)?,
                    )?;
                    entry.insert(Vec::new())
                },
                Entry::Occupied(entry) => entry.into_mut(),
            };
            reserve_one_with_retained_accounting(coordinates, &mut retained)?;
            coordinates.push((record_index, association_index));
        }
    }
    Ok((index, retained.total()))
}

struct MeasuredCursor<R: Read> {
    reader: BufReader<std::io::Take<R>>,
    hasher: Sha256,
    byte_length: u64,
    maximum_bytes: u64,
}

impl<R: Read> MeasuredCursor<R> {
    fn with_limit(reader: R, maximum_bytes: usize) -> Self {
        let maximum_bytes = u64::try_from(maximum_bytes).unwrap_or(u64::MAX);
        Self {
            // Permit one sentinel byte beyond the accepted input so growth is
            // detected without allowing BufReader to prefetch past that bound.
            reader: BufReader::with_capacity(
                64 * 1024,
                reader.take(maximum_bytes.saturating_add(1)),
            ),
            hasher: Sha256::new(),
            byte_length: 0,
            maximum_bytes,
        }
    }

    fn next_byte(&mut self) -> Result<Option<u8>, WordfenceV3ProductionError> {
        let mut byte = [0_u8; 1];
        loop {
            match self.reader.read(&mut byte) {
                Ok(0) => return Ok(None),
                Ok(1) => {
                    self.byte_length = self
                        .byte_length
                        .checked_add(1)
                        .ok_or(WordfenceV3ProductionError::InputTooLarge)?;
                    if self.byte_length > self.maximum_bytes {
                        return Err(WordfenceV3ProductionError::InputTooLarge);
                    }
                    self.hasher.update(byte);
                    return Ok(Some(byte[0]));
                },
                Ok(_) => unreachable!("one-byte read buffer cannot return more than one byte"),
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(_) => return Err(WordfenceV3ProductionError::ReadFailed),
            }
        }
    }

    fn next_non_whitespace(&mut self) -> Result<Option<u8>, WordfenceV3ProductionError> {
        loop {
            let Some(byte) = self.next_byte()? else {
                return Ok(None);
            };
            if !matches!(byte, b' ' | b'\t' | b'\r' | b'\n') {
                return Ok(Some(byte));
            }
        }
    }

    fn capture_string(&mut self) -> Result<String, WordfenceV3ProductionError> {
        let mut raw = vec![b'"'];
        let mut escaped = false;
        loop {
            let byte = self
                .next_byte()?
                .ok_or(WordfenceV3ProductionError::MalformedJson)?;
            raw.push(byte);
            if raw.len() > 256 {
                return Err(WordfenceV3ProductionError::StructuralLimitExceeded);
            }
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                break;
            }
        }
        serde_json::from_slice(&raw).map_err(|_| WordfenceV3ProductionError::MalformedJson)
    }

    fn capture_record_object(&mut self) -> Result<Vec<u8>, WordfenceV3ProductionError> {
        let mut raw = Vec::with_capacity(4096);
        raw.push(b'{');
        let mut stack = vec![b'{'];
        let mut in_string = false;
        let mut escaped = false;
        while !stack.is_empty() {
            let byte = self
                .next_byte()?
                .ok_or(WordfenceV3ProductionError::MalformedJson)?;
            raw.push(byte);
            if raw.len() > MAX_WORDFENCE_V3_RECORD_BYTES {
                return Err(WordfenceV3ProductionError::RecordTooLarge);
            }
            if in_string {
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == b'"' {
                    in_string = false;
                }
                continue;
            }
            match byte {
                b'"' => in_string = true,
                b'{' | b'[' => {
                    stack.push(byte);
                    if stack.len() > 10 {
                        return Err(WordfenceV3ProductionError::StructuralLimitExceeded);
                    }
                },
                b'}' | b']' => {
                    let expected = if byte == b'}' { b'{' } else { b'[' };
                    if stack.pop() != Some(expected) {
                        return Err(WordfenceV3ProductionError::MalformedJson);
                    }
                },
                _ => {},
            }
        }
        Ok(raw)
    }

    fn finish(self) -> (u64, [u8; 32]) {
        (self.byte_length, self.hasher.finalize().into())
    }
}

fn decode_bounded_record(bytes: &[u8]) -> Result<Value, WordfenceV3ProductionError> {
    let limits = WordfenceJsonLimits {
        maximum_nodes: MAX_WORDFENCE_V3_JSON_NODES_PER_RECORD,
        maximum_array_length: MAX_WORDFENCE_V3_ARRAY_ITEMS_PER_RECORD,
        maximum_object_members: MAX_WORDFENCE_V3_OBJECT_MEMBERS_PER_RECORD,
        maximum_key_bytes: MAX_WORDFENCE_V3_JSON_KEY_BYTES,
        maximum_string_bytes: MAX_WORDFENCE_V3_JSON_STRING_BYTES,
        maximum_depth: MAX_WORDFENCE_V3_JSON_DEPTH,
    };
    let mut budget = WordfenceJsonBudget::default();
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let value = WordfenceBoundedValueSeed {
        depth: 0,
        limits,
        budget: &mut budget,
    }
    .deserialize(&mut decoder)
    .map_err(classify_record_json_error)?;
    decoder.end().map_err(classify_record_json_error)?;
    Ok(value)
}

fn classify_record_json_error(error: serde_json::Error) -> WordfenceV3ProductionError {
    let message = error.to_string();
    if message.contains(WORDFENCE_DUPLICATE_KEY_MARKER) {
        WordfenceV3ProductionError::DuplicateKey
    } else if message.contains(WORDFENCE_JSON_LIMIT_MARKER) {
        WordfenceV3ProductionError::StructuralLimitExceeded
    } else {
        WordfenceV3ProductionError::MalformedJson
    }
}

#[derive(Clone, Copy)]
struct WordfenceJsonLimits {
    maximum_nodes: usize,
    maximum_array_length: usize,
    maximum_object_members: usize,
    maximum_key_bytes: usize,
    maximum_string_bytes: usize,
    maximum_depth: usize,
}

#[derive(Default)]
struct WordfenceJsonBudget {
    nodes: usize,
}

struct WordfenceBoundedValueSeed<'a> {
    depth: usize,
    limits: WordfenceJsonLimits,
    budget: &'a mut WordfenceJsonBudget,
}

impl<'de> DeserializeSeed<'de> for WordfenceBoundedValueSeed<'_> {
    type Value = Value;

    fn deserialize<D: de::Deserializer<'de>>(self, decoder: D) -> Result<Value, D::Error> {
        if self.depth > self.limits.maximum_depth || self.budget.nodes == self.limits.maximum_nodes
        {
            return Err(de::Error::custom(WORDFENCE_JSON_LIMIT_MARKER));
        }
        self.budget.nodes += 1;
        decoder.deserialize_any(WordfenceBoundedValueVisitor {
            depth: self.depth,
            limits: self.limits,
            budget: self.budget,
        })
    }
}

struct WordfenceBoundedValueVisitor<'a> {
    depth: usize,
    limits: WordfenceJsonLimits,
    budget: &'a mut WordfenceJsonBudget,
}

impl<'de> Visitor<'de> for WordfenceBoundedValueVisitor<'_> {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded Wordfence Production JSON")
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
        self.bounded_string(value)
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Value, E> {
        self.bounded_string(value)
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<Value, E> {
        if value.len() > self.limits.maximum_string_bytes {
            Err(de::Error::custom(WORDFENCE_JSON_LIMIT_MARKER))
        } else {
            Ok(Value::String(value))
        }
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut values: A) -> Result<Value, A::Error> {
        let mut array = Vec::new();
        loop {
            if array.len() == self.limits.maximum_array_length {
                if values.next_element::<de::IgnoredAny>()?.is_some() {
                    return Err(de::Error::custom(WORDFENCE_JSON_LIMIT_MARKER));
                }
                break;
            }
            let Some(value) = values.next_element_seed(WordfenceBoundedValueSeed {
                depth: self.depth + 1,
                limits: self.limits,
                budget: &mut *self.budget,
            })?
            else {
                break;
            };
            array.push(value);
        }
        Ok(Value::Array(array))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut fields: A) -> Result<Value, A::Error> {
        let mut object = serde_json::Map::new();
        loop {
            if object.len() == self.limits.maximum_object_members {
                if fields
                    .next_key_seed(WordfenceBoundedKeySeed {
                        maximum_bytes: self.limits.maximum_key_bytes,
                    })?
                    .is_some()
                {
                    return Err(de::Error::custom(WORDFENCE_JSON_LIMIT_MARKER));
                }
                break;
            }
            let Some(key) = fields.next_key_seed(WordfenceBoundedKeySeed {
                maximum_bytes: self.limits.maximum_key_bytes,
            })?
            else {
                break;
            };
            if object.contains_key(&key) {
                return Err(de::Error::custom(WORDFENCE_DUPLICATE_KEY_MARKER));
            }
            let value = fields.next_value_seed(WordfenceBoundedValueSeed {
                depth: self.depth + 1,
                limits: self.limits,
                budget: &mut *self.budget,
            })?;
            object.insert(key, value);
        }
        Ok(Value::Object(object))
    }
}

impl WordfenceBoundedValueVisitor<'_> {
    fn bounded_string<E: de::Error>(&self, value: &str) -> Result<Value, E> {
        if value.len() > self.limits.maximum_string_bytes {
            Err(de::Error::custom(WORDFENCE_JSON_LIMIT_MARKER))
        } else {
            Ok(Value::String(value.to_owned()))
        }
    }
}

struct WordfenceBoundedKeySeed {
    maximum_bytes: usize,
}

impl<'de> DeserializeSeed<'de> for WordfenceBoundedKeySeed {
    type Value = String;

    fn deserialize<D: de::Deserializer<'de>>(self, decoder: D) -> Result<String, D::Error> {
        decoder.deserialize_str(WordfenceBoundedKeyVisitor {
            maximum_bytes: self.maximum_bytes,
        })
    }
}

struct WordfenceBoundedKeyVisitor {
    maximum_bytes: usize,
}

impl Visitor<'_> for WordfenceBoundedKeyVisitor {
    type Value = String;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded Wordfence Production object key")
    }

    fn visit_borrowed_str<E: de::Error>(self, value: &str) -> Result<String, E> {
        self.visit_str(value)
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<String, E> {
        if value.len() > self.maximum_bytes {
            Err(de::Error::custom(WORDFENCE_JSON_LIMIT_MARKER))
        } else {
            Ok(value.to_owned())
        }
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<String, E> {
        if value.len() > self.maximum_bytes {
            Err(de::Error::custom(WORDFENCE_JSON_LIMIT_MARKER))
        } else {
            Ok(value)
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProductionRecordWire {
    id: String,
    title: String,
    software: Vec<SoftwareWire>,
    informational: bool,
    description: String,
    references: Vec<String>,
    cwe: Value,
    cvss: Value,
    cve: Value,
    cve_link: Value,
    researchers: Vec<String>,
    published: Value,
    updated: Value,
    copyrights: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SoftwareWire {
    #[serde(rename = "type")]
    kind: String,
    name: String,
    slug: String,
    affected_versions: BTreeMap<String, AffectedRangeWire>,
    patched: bool,
    patched_versions: Vec<String>,
    remediation: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AffectedRangeWire {
    from_version: String,
    from_inclusive: bool,
    to_version: String,
    to_inclusive: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CweWire {
    id: u32,
    name: String,
    description: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CvssWire {
    vector: String,
    score: Number,
    rating: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NoticePartyWire {
    notice: String,
    license: String,
    license_url: String,
}

fn decode_record(
    map_id: String,
    value: Value,
) -> Result<(WordfenceV3Record, Vec<WordfenceV3Notice>), WordfenceV3ProductionError> {
    let wire: ProductionRecordWire =
        serde_json::from_value(value).map_err(|_| WordfenceV3ProductionError::UnsupportedValue)?;
    validate_uuid(&wire.id)?;
    if wire.id != map_id {
        return Err(WordfenceV3ProductionError::ConflictingIdentity);
    }
    validate_text(&wire.title, MAX_WORDFENCE_V3_TITLE_BYTES, false)?;
    validate_text(&wire.description, MAX_WORDFENCE_V3_DESCRIPTION_BYTES, true)?;
    if wire.software.is_empty() || wire.software.len() > MAX_WORDFENCE_V3_SOFTWARE_PER_RECORD {
        return Err(WordfenceV3ProductionError::StructuralLimitExceeded);
    }
    validate_string_set(
        &wire.references,
        MAX_WORDFENCE_V3_REFERENCES,
        MAX_WORDFENCE_V3_REFERENCE_BYTES,
        validate_http_reference,
    )?;
    validate_string_sequence(
        &wire.researchers,
        MAX_WORDFENCE_V3_RESEARCHERS,
        MAX_WORDFENCE_V3_RESEARCHER_BYTES,
        |value| validate_text(value, MAX_WORDFENCE_V3_RESEARCHER_BYTES, false),
    )?;

    let cwe = decode_nullable::<CweWire>(wire.cwe)?
        .map(validate_cwe)
        .transpose()?;
    let cvss = decode_nullable::<CvssWire>(wire.cvss)?
        .map(validate_cvss)
        .transpose()?;
    let cve = decode_nullable::<String>(wire.cve)?
        .map(|value| {
            validate_cve(&value)?;
            Ok(value)
        })
        .transpose()?;
    let cve_link = decode_nullable::<String>(wire.cve_link)?
        .map(|value| {
            validate_http_reference(&value)?;
            Ok(value)
        })
        .transpose()?;
    if cve_link.is_some() && cve.is_none() {
        return Err(WordfenceV3ProductionError::ConflictingIdentity);
    }
    let published = decode_nullable::<String>(wire.published)?
        .map(|value| {
            validate_timestamp(&value)?;
            Ok(value)
        })
        .transpose()?;
    let updated = decode_nullable::<String>(wire.updated)?
        .map(|value| {
            validate_timestamp(&value)?;
            Ok(value)
        })
        .transpose()?;

    let mut software = Vec::new();
    let mut unresolved_software = Vec::new();
    for decoded in wire
        .software
        .into_iter()
        .map(|software| decode_software(&map_id, software))
    {
        match decoded? {
            DecodedSoftwareAssociation::Mapped(association) => software.push(association),
            DecodedSoftwareAssociation::Unresolved(association) => {
                unresolved_software.push(association);
            },
        }
    }
    software.sort_by(|left, right| left.key.cmp(&right.key));
    if software.windows(2).any(|pair| pair[0].key == pair[1].key) {
        return Err(WordfenceV3ProductionError::ConflictingIdentity);
    }
    unresolved_software.sort_by(|left, right| {
        left.source_component
            .cmp(&right.source_component)
            .then_with(|| left.upstream_id.cmp(&right.upstream_id))
            .then_with(|| {
                left.source_association_sha256
                    .cmp(&right.source_association_sha256)
            })
    });
    if unresolved_software.windows(2).any(|pair| {
        pair[0].upstream_id == pair[1].upstream_id
            && pair[0].source_component == pair[1].source_component
            && pair[0].source_association_sha256 == pair[1].source_association_sha256
    }) {
        return Err(WordfenceV3ProductionError::ConflictingIdentity);
    }

    let notices = decode_notices(wire.copyrights)?;
    if notices.iter().any(|notice| notice.party == "defiant")
        && !wire
            .references
            .iter()
            .any(|reference| is_official_wordfence_vulnerability_reference(reference))
    {
        return Err(WordfenceV3ProductionError::UnsupportedValue);
    }
    let mut notice_ids = notices
        .iter()
        .map(|notice| notice.id.clone())
        .collect::<Vec<_>>();
    notice_ids.sort();

    let mut references = wire.references;
    references.sort();
    let mut researchers = wire.researchers;
    researchers.sort();
    Ok((
        WordfenceV3Record {
            upstream_id: map_id,
            title: wire.title,
            informational: wire.informational,
            description: wire.description,
            references,
            cwe,
            cvss,
            cve,
            cve_link,
            researchers,
            published,
            updated,
            notice_ids,
            software,
            unresolved_software,
        },
        notices,
    ))
}

enum DecodedSoftwareAssociation {
    Mapped(WordfenceV3SoftwareAssociation),
    Unresolved(WordfenceV3UnresolvedSoftwareAssociation),
}

fn decode_software(
    upstream_id: &str,
    wire: SoftwareWire,
) -> Result<DecodedSoftwareAssociation, WordfenceV3ProductionError> {
    let kind = match wire.kind.as_str() {
        "core" => WordPressComponentKind::Core,
        "plugin" => WordPressComponentKind::Plugin,
        "theme" => WordPressComponentKind::Theme,
        _ => return Err(WordfenceV3ProductionError::UnsupportedValue),
    };
    validate_text(&wire.name, MAX_WORDFENCE_V3_NAME_BYTES, false)?;
    validate_source_slug(&wire.slug)?;
    let source_component = WordfenceV3SourceComponentIdentity {
        kind,
        slug: wire.slug,
    };
    let mapped = WordPressComponentIdentity::new(kind, source_component.slug.clone())
        .map(|component| (component, WordfenceV3IdentityMapping::Exact))
        .or_else(|_| {
            let folded = source_component.slug.to_ascii_lowercase();
            WordPressComponentIdentity::new(kind, folded).map(|component| {
                (
                    component,
                    WordfenceV3IdentityMapping::AsciiCaseFoldCandidate,
                )
            })
        })
        .ok();
    if wire.affected_versions.len() > MAX_WORDFENCE_V3_RANGES_PER_ASSOCIATION
        || wire.patched_versions.len() > MAX_WORDFENCE_V3_PATCHED_VERSIONS
    {
        return Err(WordfenceV3ProductionError::StructuralLimitExceeded);
    }
    let mut affected_ranges = wire
        .affected_versions
        .into_iter()
        .map(|(label, range)| decode_range(label, range))
        .collect::<Result<Vec<_>, _>>()?;
    affected_ranges.sort();
    let mut patched_versions = wire.patched_versions;
    for version in &patched_versions {
        validate_version(version, false)?;
    }
    patched_versions.sort();
    if patched_versions.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(WordfenceV3ProductionError::ConflictingIdentity);
    }
    validate_text(&wire.remediation, MAX_WORDFENCE_V3_REMEDIATION_BYTES, true)?;
    let source_association_sha256 = source_association_digest(
        &source_component,
        &wire.name,
        &affected_ranges,
        wire.patched,
        &patched_versions,
        &wire.remediation,
    );
    let upstream_id = upstream_id.to_owned();
    Ok(if let Some((component, identity_mapping)) = mapped {
        DecodedSoftwareAssociation::Mapped(WordfenceV3SoftwareAssociation {
            key: WordfenceV3AssociationKey {
                upstream_id,
                component,
                source_component,
                source_association_sha256,
            },
            identity_mapping,
            identity_collision_raw_count: None,
            display_name: wire.name,
            affected_ranges,
            patched: wire.patched,
            patched_versions,
            remediation: wire.remediation,
        })
    } else {
        DecodedSoftwareAssociation::Unresolved(WordfenceV3UnresolvedSoftwareAssociation {
            upstream_id,
            source_component,
            source_association_sha256,
            display_name: wire.name,
            affected_ranges,
            patched: wire.patched,
            patched_versions,
            remediation: wire.remediation,
        })
    })
}

fn decode_range(
    label: String,
    wire: AffectedRangeWire,
) -> Result<WordfenceV3AffectedRange, WordfenceV3ProductionError> {
    validate_text(&label, MAX_WORDFENCE_V3_RANGE_LABEL_BYTES, false)?;
    Ok(WordfenceV3AffectedRange {
        label,
        from: WordfenceV3RangeEndpoint {
            value: decode_range_value(wire.from_version)?,
            inclusive: wire.from_inclusive,
        },
        to: WordfenceV3RangeEndpoint {
            value: decode_range_value(wire.to_version)?,
            inclusive: wire.to_inclusive,
        },
    })
}

fn decode_range_value(value: String) -> Result<WordfenceV3RangeValue, WordfenceV3ProductionError> {
    if value == "*" {
        Ok(WordfenceV3RangeValue::Any)
    } else {
        validate_version(&value, false)?;
        Ok(WordfenceV3RangeValue::Declared(value))
    }
}

fn decode_notices(value: Value) -> Result<Vec<WordfenceV3Notice>, WordfenceV3ProductionError> {
    if value.is_null() {
        return Ok(Vec::new());
    }
    let mut object = value
        .as_object()
        .cloned()
        .ok_or(WordfenceV3ProductionError::UnsupportedValue)?;
    let message = object
        .remove("message")
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or(WordfenceV3ProductionError::UnsupportedValue)?;
    validate_text(&message, MAX_WORDFENCE_V3_NOTICE_TEXT_BYTES, true)?;
    if object.is_empty() || object.len() > MAX_WORDFENCE_V3_NOTICE_PARTIES {
        return Err(WordfenceV3ProductionError::StructuralLimitExceeded);
    }
    let mut notices = Vec::with_capacity(object.len());
    for (party, value) in object {
        validate_identifier(&party, 128)?;
        let wire: NoticePartyWire = serde_json::from_value(value)
            .map_err(|_| WordfenceV3ProductionError::UnsupportedValue)?;
        validate_text(&wire.notice, MAX_WORDFENCE_V3_NOTICE_TEXT_BYTES, true)?;
        validate_text(&wire.license, MAX_WORDFENCE_V3_NOTICE_TEXT_BYTES, true)?;
        validate_http_reference(&wire.license_url)?;
        let id = notice_id(
            &message,
            &party,
            &wire.notice,
            &wire.license,
            &wire.license_url,
        );
        notices.push(WordfenceV3Notice {
            id,
            message: message.clone(),
            party,
            notice: wire.notice,
            license: wire.license,
            license_url: wire.license_url,
        });
    }
    notices.sort();
    Ok(notices)
}

fn decode_nullable<T: for<'de> Deserialize<'de>>(
    value: Value,
) -> Result<Option<T>, WordfenceV3ProductionError> {
    if value.is_null() {
        Ok(None)
    } else {
        serde_json::from_value(value)
            .map(Some)
            .map_err(|_| WordfenceV3ProductionError::UnsupportedValue)
    }
}

fn validate_cwe(wire: CweWire) -> Result<WordfenceV3Cwe, WordfenceV3ProductionError> {
    if wire.id == 0 {
        return Err(WordfenceV3ProductionError::UnsupportedValue);
    }
    validate_text(&wire.name, MAX_WORDFENCE_V3_NAME_BYTES, false)?;
    validate_text(&wire.description, MAX_WORDFENCE_V3_DESCRIPTION_BYTES, true)?;
    Ok(WordfenceV3Cwe {
        id: wire.id,
        name: wire.name,
        description: wire.description,
    })
}

fn validate_cvss(wire: CvssWire) -> Result<WordfenceV3Cvss, WordfenceV3ProductionError> {
    validate_text(&wire.vector, MAX_WORDFENCE_V3_CVSS_VECTOR_BYTES, false)?;
    if !wire.vector.starts_with("CVSS:3.0/") && !wire.vector.starts_with("CVSS:3.1/") {
        return Err(WordfenceV3ProductionError::UnsupportedValue);
    }
    // JSON numeric spellings are semantically equivalent. Normalize once,
    // then retain only the bounded score grammar shared by the saved-audit
    // writer and strict display-only reader.
    let score = wire.score.to_string();
    let mut score_parts = score.split('.');
    let integer = score_parts.next().unwrap_or_default();
    let fraction = score_parts.next();
    if score_parts.next().is_some()
        || integer.is_empty()
        || !integer.bytes().all(|byte| byte.is_ascii_digit())
        || (integer.len() > 1 && integer.starts_with('0'))
        || fraction.is_some_and(|value| {
            value.len() != 1 || !value.bytes().all(|byte| byte.is_ascii_digit())
        })
    {
        return Err(WordfenceV3ProductionError::UnsupportedValue);
    }
    match integer.parse::<u8>() {
        Ok(0..=9) => {},
        Ok(10) if fraction.is_none_or(|value| value == "0") => {},
        _ => return Err(WordfenceV3ProductionError::UnsupportedValue),
    }
    let rating = match wire.rating.as_str() {
        "None" => WordfenceV3CvssRating::None,
        "Low" => WordfenceV3CvssRating::Low,
        "Medium" => WordfenceV3CvssRating::Medium,
        "High" => WordfenceV3CvssRating::High,
        "Critical" => WordfenceV3CvssRating::Critical,
        _ => return Err(WordfenceV3ProductionError::UnsupportedValue),
    };
    Ok(WordfenceV3Cvss {
        vector: wire.vector,
        score,
        rating,
    })
}

fn validate_uuid(value: &str) -> Result<(), WordfenceV3ProductionError> {
    if value.len() != 36
        || !value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
        })
    {
        return Err(WordfenceV3ProductionError::UnsupportedValue);
    }
    Ok(())
}

fn validate_cve(value: &str) -> Result<(), WordfenceV3ProductionError> {
    if value.len() > MAX_WORDFENCE_V3_CVE_BYTES {
        return Err(WordfenceV3ProductionError::UnsupportedValue);
    }
    let mut parts = value.split('-');
    if parts.next() != Some("CVE")
        || parts
            .next()
            .is_none_or(|year| year.len() != 4 || !year.bytes().all(|b| b.is_ascii_digit()))
        || parts
            .next()
            .is_none_or(|id| id.len() < 4 || !id.bytes().all(|b| b.is_ascii_digit()))
        || parts.next().is_some()
    {
        return Err(WordfenceV3ProductionError::UnsupportedValue);
    }
    Ok(())
}

fn validate_timestamp(value: &str) -> Result<(), WordfenceV3ProductionError> {
    if value.len() != 19
        || value.as_bytes()[4] != b'-'
        || value.as_bytes()[7] != b'-'
        || value.as_bytes()[10] != b' '
        || value.as_bytes()[13] != b':'
        || value.as_bytes()[16] != b':'
        || !value
            .bytes()
            .enumerate()
            .all(|(index, byte)| matches!(index, 4 | 7 | 10 | 13 | 16) || byte.is_ascii_digit())
    {
        return Err(WordfenceV3ProductionError::UnsupportedValue);
    }
    let month = parse_two_digits(value, 5)?;
    let day = parse_two_digits(value, 8)?;
    let hour = parse_two_digits(value, 11)?;
    let minute = parse_two_digits(value, 14)?;
    let second = parse_two_digits(value, 17)?;
    let year = value[..4]
        .parse::<u16>()
        .map_err(|_| WordfenceV3ProductionError::UnsupportedValue)?;
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year % 400 == 0 || (year % 4 == 0 && year % 100 != 0) => 29,
        2 => 28,
        _ => 0,
    };
    if day == 0 || day > days_in_month || hour > 23 || minute > 59 || second > 59 {
        return Err(WordfenceV3ProductionError::UnsupportedValue);
    }
    Ok(())
}

fn parse_two_digits(value: &str, start: usize) -> Result<u8, WordfenceV3ProductionError> {
    value[start..start + 2]
        .parse()
        .map_err(|_| WordfenceV3ProductionError::UnsupportedValue)
}

fn validate_version(value: &str, allow_wildcard: bool) -> Result<(), WordfenceV3ProductionError> {
    if value.is_empty()
        || value.len() > MAX_WORDFENCE_V3_VERSION_BYTES
        || (!allow_wildcard && value == "*")
        || value.chars().any(char::is_control)
        || value.chars().next().is_some_and(char::is_whitespace)
        || value.chars().next_back().is_some_and(char::is_whitespace)
    {
        return Err(WordfenceV3ProductionError::UnsupportedValue);
    }
    Ok(())
}

fn validate_identifier(value: &str, maximum: usize) -> Result<(), WordfenceV3ProductionError> {
    if value.is_empty()
        || value.len() > maximum
        || !value.is_ascii()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(WordfenceV3ProductionError::UnsupportedValue);
    }
    Ok(())
}

fn validate_source_slug(value: &str) -> Result<(), WordfenceV3ProductionError> {
    // The provider field is retained as an opaque, inert source identifier.
    // Printable punctuation is not interpreted as a path or URL and will fail
    // canonical matching below; controls, non-ASCII text and oversize values
    // remain structural rejections.
    if value.is_empty()
        || value.len() > MAX_WORDFENCE_V3_SOURCE_SLUG_BYTES
        || !value.is_ascii()
        || value.bytes().any(|byte| byte.is_ascii_control())
        || !value.bytes().any(|byte| byte.is_ascii_alphanumeric())
    {
        return Err(WordfenceV3ProductionError::UnsupportedValue);
    }
    Ok(())
}

fn validate_text(
    value: &str,
    maximum: usize,
    allow_empty: bool,
) -> Result<(), WordfenceV3ProductionError> {
    if (!allow_empty && value.is_empty())
        || value.len() > maximum
        || value
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    {
        return Err(WordfenceV3ProductionError::UnsupportedValue);
    }
    Ok(())
}

fn validate_http_reference(value: &str) -> Result<(), WordfenceV3ProductionError> {
    validate_text(value, MAX_WORDFENCE_V3_REFERENCE_BYTES, false)?;
    let parsed = Url::parse(value).map_err(|_| WordfenceV3ProductionError::UnsupportedValue)?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err(WordfenceV3ProductionError::UnsupportedValue);
    }
    Ok(())
}

fn is_official_wordfence_vulnerability_reference(value: &str) -> bool {
    const PREFIX: &str = "/threat-intel/vulnerabilities/";
    Url::parse(value).ok().is_some_and(|url| {
        matches!(url.scheme(), "http" | "https")
            && url.host_str() == Some("www.wordfence.com")
            && url.username().is_empty()
            && url.password().is_none()
            && url.port().is_none()
            && url.as_str() == value
            && url.path().starts_with(PREFIX)
            && url.path().len() > PREFIX.len()
            && has_supported_wordfence_reference_query(&url)
            && url.fragment().is_none()
    })
}

fn has_supported_wordfence_reference_query(url: &Url) -> bool {
    const MAX_SOURCE_VALUE_BYTES: usize = 64;
    // The accepted Production form may attach one inert source marker to the
    // record URL. Keep the allowance narrower than general URL query syntax.
    match url.query() {
        None => true,
        Some(query) => query.strip_prefix("source=").is_some_and(|value| {
            !value.is_empty()
                && value.len() <= MAX_SOURCE_VALUE_BYTES
                && value.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
                })
        }),
    }
}

fn validate_string_set(
    values: &[String],
    maximum_count: usize,
    maximum_bytes: usize,
    validate: impl Fn(&str) -> Result<(), WordfenceV3ProductionError>,
) -> Result<(), WordfenceV3ProductionError> {
    if values.len() > maximum_count {
        return Err(WordfenceV3ProductionError::StructuralLimitExceeded);
    }
    let mut seen = BTreeSet::new();
    for value in values {
        if value.len() > maximum_bytes {
            return Err(WordfenceV3ProductionError::UnsupportedValue);
        }
        validate(value)?;
        if !seen.insert(value) {
            return Err(WordfenceV3ProductionError::ConflictingIdentity);
        }
    }
    Ok(())
}

fn validate_string_sequence(
    values: &[String],
    maximum_count: usize,
    maximum_bytes: usize,
    validate: impl Fn(&str) -> Result<(), WordfenceV3ProductionError>,
) -> Result<(), WordfenceV3ProductionError> {
    if values.len() > maximum_count {
        return Err(WordfenceV3ProductionError::StructuralLimitExceeded);
    }
    for value in values {
        if value.len() > maximum_bytes {
            return Err(WordfenceV3ProductionError::UnsupportedValue);
        }
        validate(value)?;
    }
    Ok(())
}

fn notice_id(message: &str, party: &str, notice: &str, license: &str, url: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"termivar.wordfence-v3.notice/v1\0");
    for value in [message, party, notice, license, url] {
        frame(&mut digest, value.as_bytes());
    }
    let digest = digest.finalize();
    format!("wordfence-notice-sha256:{digest:x}")
}

fn semantic_digest(
    records: &[WordfenceV3Record],
    notices: &[WordfenceV3Notice],
    identity_counts: &WordfenceV3IdentityCounts,
    requires_expanded_semantics: bool,
) -> [u8; 32] {
    if !identity_counts.requires_source_identity_mapping() && !requires_expanded_semantics {
        return semantic_digest_v1(records, notices);
    }

    let mut digest = Sha256::new();
    digest.update(b"termivar.wordfence-v3-production.semantic/v2\0");
    frame(&mut digest, WORDFENCE_V3_SOURCE_NAMESPACE.as_bytes());
    let mapping_revision = if identity_counts.requires_source_identity_mapping() {
        WORDFENCE_V3_MAPPING_REVISION_V2
    } else {
        WORDFENCE_V3_MAPPING_REVISION
    };
    frame(&mut digest, mapping_revision.as_bytes());
    frame(&mut digest, WORDFENCE_V3_IDENTITY_MAPPING_POLICY.as_bytes());
    for value in [
        identity_counts.exact,
        identity_counts.candidate,
        identity_counts.ambiguous,
        identity_counts.unresolved,
    ] {
        frame_usize(&mut digest, value);
    }
    frame_usize(&mut digest, records.len());
    for record in records {
        hash_record_v2(&mut digest, record);
    }
    hash_notices(&mut digest, notices);
    digest.finalize().into()
}

fn semantic_digest_v1(records: &[WordfenceV3Record], notices: &[WordfenceV3Notice]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"termivar.wordfence-v3-production.semantic/v1\0");
    frame(&mut digest, WORDFENCE_V3_SOURCE_NAMESPACE.as_bytes());
    frame(&mut digest, WORDFENCE_V3_MAPPING_REVISION.as_bytes());
    frame_usize(&mut digest, records.len());
    for record in records {
        hash_record_v1(&mut digest, record);
    }
    hash_notices(&mut digest, notices);
    digest.finalize().into()
}

fn hash_notices(digest: &mut Sha256, notices: &[WordfenceV3Notice]) {
    frame_usize(digest, notices.len());
    for notice in notices {
        for value in [
            notice.id.as_str(),
            notice.message.as_str(),
            notice.party.as_str(),
            notice.notice.as_str(),
            notice.license.as_str(),
            notice.license_url.as_str(),
        ] {
            frame(digest, value.as_bytes());
        }
    }
}

fn hash_record_v1(digest: &mut Sha256, record: &WordfenceV3Record) {
    hash_record_common(digest, record);
    frame_usize(digest, record.software.len());
    for association in &record.software {
        hash_association_common(digest, association);
    }
}

fn hash_record_v2(digest: &mut Sha256, record: &WordfenceV3Record) {
    hash_record_common(digest, record);
    frame_usize(digest, record.software.len());
    for association in &record.software {
        digest.update([association.source_component().kind() as u8]);
        frame(digest, association.source_component().slug().as_bytes());
        frame(digest, association.identity_mapping().as_str().as_bytes());
        match association.identity_collision_raw_count() {
            Some(count) => {
                digest.update([1]);
                frame_usize(digest, count);
            },
            None => digest.update([0]),
        }
        hash_association_common(digest, association);
    }
    frame_usize(digest, record.unresolved_software.len());
    for association in &record.unresolved_software {
        digest.update([association.source_component.kind as u8]);
        frame(digest, association.source_component.slug.as_bytes());
        frame(digest, association.display_name.as_bytes());
        hash_association_values(
            digest,
            &association.affected_ranges,
            association.patched,
            &association.patched_versions,
            &association.remediation,
        );
    }
}

fn hash_record_common(digest: &mut Sha256, record: &WordfenceV3Record) {
    frame(digest, record.upstream_id.as_bytes());
    frame(digest, record.title.as_bytes());
    digest.update([u8::from(record.informational)]);
    frame(digest, record.description.as_bytes());
    hash_strings(digest, &record.references);
    match &record.cwe {
        Some(cwe) => {
            digest.update([1]);
            digest.update(cwe.id.to_be_bytes());
            frame(digest, cwe.name.as_bytes());
            frame(digest, cwe.description.as_bytes());
        },
        None => digest.update([0]),
    }
    match &record.cvss {
        Some(cvss) => {
            digest.update([1]);
            frame(digest, cvss.vector.as_bytes());
            frame(digest, cvss.score.as_bytes());
            digest.update([cvss.rating as u8]);
        },
        None => digest.update([0]),
    }
    hash_optional_string(digest, record.cve.as_deref());
    hash_optional_string(digest, record.cve_link.as_deref());
    hash_strings(digest, &record.researchers);
    hash_optional_string(digest, record.published.as_deref());
    hash_optional_string(digest, record.updated.as_deref());
    hash_strings(digest, &record.notice_ids);
}

fn hash_association_common(digest: &mut Sha256, association: &WordfenceV3SoftwareAssociation) {
    digest.update([association.component().kind() as u8]);
    frame(digest, association.component().slug().as_bytes());
    frame(digest, association.display_name.as_bytes());
    hash_association_values(
        digest,
        &association.affected_ranges,
        association.patched,
        &association.patched_versions,
        &association.remediation,
    );
}

fn source_association_digest(
    source_component: &WordfenceV3SourceComponentIdentity,
    display_name: &str,
    affected_ranges: &[WordfenceV3AffectedRange],
    patched: bool,
    patched_versions: &[String],
    remediation: &str,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"termivar.wordfence-v3.source-association/v1\0");
    digest.update([source_component.kind as u8]);
    frame(&mut digest, source_component.slug.as_bytes());
    frame(&mut digest, display_name.as_bytes());
    hash_association_values(
        &mut digest,
        affected_ranges,
        patched,
        patched_versions,
        remediation,
    );
    digest.finalize().into()
}

fn hash_association_values(
    digest: &mut Sha256,
    affected_ranges: &[WordfenceV3AffectedRange],
    patched: bool,
    patched_versions: &[String],
    remediation: &str,
) {
    frame_usize(digest, affected_ranges.len());
    for range in affected_ranges {
        frame(digest, range.label.as_bytes());
        frame(digest, range.from.value.declared().as_bytes());
        digest.update([u8::from(range.from.inclusive)]);
        frame(digest, range.to.value.declared().as_bytes());
        digest.update([u8::from(range.to.inclusive)]);
    }
    digest.update([u8::from(patched)]);
    hash_strings(digest, patched_versions);
    frame(digest, remediation.as_bytes());
}

fn hash_strings(digest: &mut Sha256, values: &[String]) {
    frame_usize(digest, values.len());
    for value in values {
        frame(digest, value.as_bytes());
    }
}

fn hash_optional_string(digest: &mut Sha256, value: Option<&str>) {
    if let Some(value) = value {
        digest.update([1]);
        frame(digest, value.as_bytes());
    } else {
        digest.update([0]);
    }
}

fn frame(digest: &mut Sha256, value: &[u8]) {
    digest.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(value);
}

fn frame_usize(digest: &mut Sha256, value: usize) {
    digest.update(u64::try_from(value).unwrap_or(u64::MAX).to_be_bytes());
}

fn retained_import_bytes(
    records: &[WordfenceV3Record],
    records_capacity: usize,
    notices: &[WordfenceV3Notice],
    notices_capacity: usize,
    component_index: &ComponentAssociationIndex,
    maximum: usize,
) -> Result<usize, WordfenceV3ProductionError> {
    let mut retained = RetainedBudget::with_base(
        maximum,
        retained_records_and_notices_bytes(
            records,
            records_capacity,
            notices,
            notices_capacity,
            maximum,
        )?,
    )?;
    account_component_index(&mut retained, component_index)?;
    Ok(retained.total())
}

fn retained_records_and_notices_bytes(
    records: &[WordfenceV3Record],
    records_capacity: usize,
    notices: &[WordfenceV3Notice],
    notices_capacity: usize,
    maximum: usize,
) -> Result<usize, WordfenceV3ProductionError> {
    let mut retained =
        RetainedBudget::with_base(maximum, size_of::<WordfenceV3ProductionImport>())?;
    retained.add(
        records_capacity
            .checked_mul(size_of::<WordfenceV3Record>())
            .ok_or(WordfenceV3ProductionError::RetainedDataTooLarge)?,
    )?;
    for record in records {
        retained.add(record_dynamic_bytes(record)?)?;
    }
    retained.add(
        notices_capacity
            .checked_mul(size_of::<WordfenceV3Notice>())
            .ok_or(WordfenceV3ProductionError::RetainedDataTooLarge)?,
    )?;
    for notice in notices {
        retained.add(notice_dynamic_bytes(notice)?)?;
    }
    Ok(retained.total())
}

fn account_component_index(
    retained: &mut RetainedBudget,
    component_index: &ComponentAssociationIndex,
) -> Result<(), WordfenceV3ProductionError> {
    for (component, coordinates) in component_index {
        retained.add_btree_entry(
            size_of::<WordPressComponentIdentity>()
                .checked_add(size_of::<Vec<AssociationCoordinate>>())
                .and_then(|bytes| bytes.checked_add(component.slug.capacity()))
                .and_then(|bytes| {
                    bytes.checked_add(
                        coordinates
                            .capacity()
                            .checked_mul(size_of::<AssociationCoordinate>())?,
                    )
                })
                .ok_or(WordfenceV3ProductionError::RetainedDataTooLarge)?,
        )?;
    }
    Ok(())
}

fn record_dynamic_bytes(record: &WordfenceV3Record) -> Result<usize, WordfenceV3ProductionError> {
    let mut retained = RetainedBudget::with_base(usize::MAX, 0)?;
    for value in [&record.upstream_id, &record.title, &record.description] {
        retained.add(value.capacity())?;
    }
    for value in [
        record.cve.as_ref(),
        record.cve_link.as_ref(),
        record.published.as_ref(),
        record.updated.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        retained.add(value.capacity())?;
    }
    account_string_vec(
        &mut retained,
        &record.references,
        record.references.capacity(),
    )?;
    account_string_vec(
        &mut retained,
        &record.researchers,
        record.researchers.capacity(),
    )?;
    account_string_vec(
        &mut retained,
        &record.notice_ids,
        record.notice_ids.capacity(),
    )?;
    if let Some(cwe) = &record.cwe {
        retained.add(cwe.name.capacity())?;
        retained.add(cwe.description.capacity())?;
    }
    if let Some(cvss) = &record.cvss {
        retained.add(cvss.vector.capacity())?;
        retained.add(cvss.score.capacity())?;
    }
    retained.add(
        record
            .software
            .capacity()
            .checked_mul(size_of::<WordfenceV3SoftwareAssociation>())
            .ok_or(WordfenceV3ProductionError::RetainedDataTooLarge)?,
    )?;
    for association in &record.software {
        retained.add(association.key.upstream_id.capacity())?;
        retained.add(association.key.component.slug.capacity())?;
        retained.add(association.key.source_component.slug.capacity())?;
        retained.add(association.display_name.capacity())?;
        retained.add(association.remediation.capacity())?;
        account_string_vec(
            &mut retained,
            &association.patched_versions,
            association.patched_versions.capacity(),
        )?;
        retained.add(
            association
                .affected_ranges
                .capacity()
                .checked_mul(size_of::<WordfenceV3AffectedRange>())
                .ok_or(WordfenceV3ProductionError::RetainedDataTooLarge)?,
        )?;
        for range in &association.affected_ranges {
            retained.add(range.label.capacity())?;
            if let WordfenceV3RangeValue::Declared(value) = &range.from.value {
                retained.add(value.capacity())?;
            }
            if let WordfenceV3RangeValue::Declared(value) = &range.to.value {
                retained.add(value.capacity())?;
            }
        }
    }
    retained.add(
        record
            .unresolved_software
            .capacity()
            .checked_mul(size_of::<WordfenceV3UnresolvedSoftwareAssociation>())
            .ok_or(WordfenceV3ProductionError::RetainedDataTooLarge)?,
    )?;
    for association in &record.unresolved_software {
        retained.add(association.upstream_id.capacity())?;
        retained.add(association.source_component.slug.capacity())?;
        retained.add(association.display_name.capacity())?;
        retained.add(association.remediation.capacity())?;
        account_string_vec(
            &mut retained,
            &association.patched_versions,
            association.patched_versions.capacity(),
        )?;
        retained.add(
            association
                .affected_ranges
                .capacity()
                .checked_mul(size_of::<WordfenceV3AffectedRange>())
                .ok_or(WordfenceV3ProductionError::RetainedDataTooLarge)?,
        )?;
        for range in &association.affected_ranges {
            retained.add(range.label.capacity())?;
            if let WordfenceV3RangeValue::Declared(value) = &range.from.value {
                retained.add(value.capacity())?;
            }
            if let WordfenceV3RangeValue::Declared(value) = &range.to.value {
                retained.add(value.capacity())?;
            }
        }
    }
    Ok(retained.total())
}

fn notice_dynamic_bytes(notice: &WordfenceV3Notice) -> Result<usize, WordfenceV3ProductionError> {
    let mut retained = RetainedBudget::with_base(usize::MAX, 0)?;
    for value in [
        &notice.id,
        &notice.message,
        &notice.party,
        &notice.notice,
        &notice.license,
        &notice.license_url,
    ] {
        retained.add(value.capacity())?;
    }
    Ok(retained.total())
}

fn account_string_vec(
    retained: &mut RetainedBudget,
    values: &[String],
    capacity: usize,
) -> Result<(), WordfenceV3ProductionError> {
    retained.add(
        capacity
            .checked_mul(size_of::<String>())
            .ok_or(WordfenceV3ProductionError::RetainedDataTooLarge)?,
    )?;
    for value in values {
        retained.add(value.capacity())?;
    }
    Ok(())
}

fn reserve_one_with_retained_accounting<T>(
    values: &mut Vec<T>,
    retained: &mut RetainedBudget,
) -> Result<(), WordfenceV3ProductionError> {
    if values.len() < values.capacity() {
        return Ok(());
    }
    let required = values
        .len()
        .checked_add(1)
        .ok_or(WordfenceV3ProductionError::RetainedDataTooLarge)?;
    let planned_capacity = values
        .capacity()
        .checked_mul(2)
        .unwrap_or(usize::MAX)
        .max(4)
        .max(required);
    reserve_exact_capacity_with_retained_accounting(values, planned_capacity, retained)
}

fn reserve_exact_capacity_with_retained_accounting<T>(
    values: &mut Vec<T>,
    requested_capacity: usize,
    retained: &mut RetainedBudget,
) -> Result<(), WordfenceV3ProductionError> {
    let previous_capacity = values.capacity();
    if requested_capacity <= previous_capacity {
        return Ok(());
    }
    let planned_delta = requested_capacity
        .checked_sub(previous_capacity)
        .and_then(|capacity| capacity.checked_mul(size_of::<T>()))
        .ok_or(WordfenceV3ProductionError::RetainedDataTooLarge)?;
    // Charge the requested allocation before making it. This prevents an
    // attacker-controlled growth boundary from allocating first and only then
    // discovering that the retained-data ceiling was crossed.
    retained.add(planned_delta)?;
    values
        .try_reserve_exact(
            requested_capacity
                .checked_sub(values.len())
                .ok_or(WordfenceV3ProductionError::RetainedDataTooLarge)?,
        )
        .map_err(|_| WordfenceV3ProductionError::RetainedDataTooLarge)?;
    let unplanned_capacity = values.capacity().saturating_sub(requested_capacity);
    retained.add(
        unplanned_capacity
            .checked_mul(size_of::<T>())
            .ok_or(WordfenceV3ProductionError::RetainedDataTooLarge)?,
    )
}

struct RetainedBudget {
    total: usize,
    maximum: usize,
}

impl RetainedBudget {
    fn with_base(maximum: usize, base: usize) -> Result<Self, WordfenceV3ProductionError> {
        if base > maximum {
            return Err(WordfenceV3ProductionError::RetainedDataTooLarge);
        }
        Ok(Self {
            total: base,
            maximum,
        })
    }

    fn add(&mut self, bytes: usize) -> Result<(), WordfenceV3ProductionError> {
        self.total = self
            .total
            .checked_add(bytes)
            .ok_or(WordfenceV3ProductionError::RetainedDataTooLarge)?;
        if self.total > self.maximum {
            return Err(WordfenceV3ProductionError::RetainedDataTooLarge);
        }
        Ok(())
    }

    fn add_btree_entry(&mut self, stored_bytes: usize) -> Result<(), WordfenceV3ProductionError> {
        self.add(
            stored_bytes
                .checked_add(CONSERVATIVE_BTREE_NODE_BYTES_PER_ENTRY)
                .ok_or(WordfenceV3ProductionError::RetainedDataTooLarge)?,
        )
    }

    fn add_notice_map_entry(
        &mut self,
        map_key: &String,
        notice: &WordfenceV3Notice,
    ) -> Result<(), WordfenceV3ProductionError> {
        self.add_btree_entry(
            size_of::<String>()
                .checked_add(size_of::<WordfenceV3Notice>())
                .and_then(|bytes| bytes.checked_add(map_key.capacity()))
                .and_then(|bytes| bytes.checked_add(notice_dynamic_bytes(notice).ok()?))
                .ok_or(WordfenceV3ProductionError::RetainedDataTooLarge)?,
        )
    }

    const fn total(&self) -> usize {
        self.total
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &[u8] = include_bytes!(
        "../../../../docs/examples/wordpress-review/wordfence-v3/production.synthetic.json"
    );
    const FIRST_ID: &str = "00000000-0000-4000-8000-000000000001";
    const SECOND_ID: &str = "00000000-0000-4000-8000-000000000002";
    const FIXTURE_SHA256: [u8; 32] = [
        0xd9, 0xed, 0x31, 0x40, 0xf4, 0x4a, 0xe1, 0xe0, 0xa3, 0x74, 0x6b, 0xeb, 0x99, 0x37, 0xde,
        0x2d, 0x82, 0x9d, 0x28, 0xc0, 0x68, 0x10, 0x11, 0x20, 0xa9, 0x10, 0x4c, 0x33, 0x49, 0x90,
        0x1d, 0xb7,
    ];
    // Independently calculated from the documented v1 framing contract. This
    // is intentionally not produced by the parser or digest helper under test.
    const FIXTURE_SEMANTIC_SHA256: [u8; 32] = [
        0xc7, 0xaf, 0xf0, 0x23, 0x31, 0xe8, 0x54, 0x6f, 0x14, 0x37, 0xa8, 0xd9, 0x59, 0x40, 0xdd,
        0x80, 0x32, 0x17, 0x49, 0x08, 0x04, 0x5f, 0xed, 0x98, 0x7d, 0x09, 0x0a, 0x96, 0xfb, 0x53,
        0x5e, 0xca,
    ];

    #[test]
    fn synthetic_production_fixture_is_streamed_into_the_reviewed_typed_contract() {
        let import = parse_wordfence_v3_production(FIXTURE).unwrap();
        assert_eq!(import.byte_length(), FIXTURE.len() as u64);
        assert_eq!(import.sha256(), &FIXTURE_SHA256);
        assert_eq!(import.record_count(), 2);
        assert_eq!(import.software_association_count(), 3);
        assert_eq!(import.affected_range_count(), 4);
        assert_eq!(import.notices().len(), 1);
        assert!(import.retained_bytes() < MAX_WORDFENCE_V3_RETAINED_BYTES);
        assert_ne!(import.sha256(), import.semantic_sha256());
        assert_eq!(import.semantic_sha256(), &FIXTURE_SEMANTIC_SHA256);
        assert_eq!(import.mapping_revision(), WORDFENCE_V3_MAPPING_REVISION);
        assert_eq!(import.resource_policy(), WORDFENCE_V3_RESOURCE_POLICY_V1);
        assert_eq!(import.identity_counts().exact(), 3);
        assert_eq!(import.identity_counts().candidate(), 0);
        assert_eq!(import.identity_counts().ambiguous(), 0);
        assert_eq!(import.identity_counts().unresolved(), 0);

        let plugin = WordPressComponentIdentity::new(
            WordPressComponentKind::Plugin,
            "termivar-fixture-component",
        )
        .unwrap();
        let theme = WordPressComponentIdentity::new(
            WordPressComponentKind::Theme,
            "termivar-fixture-component",
        )
        .unwrap();
        let plugin_matches = import.associations_for(&plugin).collect::<Vec<_>>();
        let theme_matches = import.associations_for(&theme).collect::<Vec<_>>();
        assert_eq!(plugin_matches.len(), 1);
        assert_eq!(theme_matches.len(), 1);
        assert_eq!(plugin_matches[0].upstream_id(), FIRST_ID);
        assert_eq!(plugin_matches[0].association().affected_ranges().len(), 2);
        assert_eq!(theme_matches[0].association().affected_ranges().len(), 1);
        assert_eq!(
            plugin_matches[0].association().key().source_namespace(),
            WORDFENCE_V3_SOURCE_NAMESPACE
        );
        assert_eq!(
            plugin_matches[0].association().source_component().slug(),
            "termivar-fixture-component"
        );
        assert_eq!(
            plugin_matches[0].association().identity_mapping(),
            WordfenceV3IdentityMapping::Exact
        );

        let notice = &import.notices()[0];
        assert!(notice.id().starts_with("wordfence-notice-sha256:"));
        assert_eq!(notice.id().len(), "wordfence-notice-sha256:".len() + 64);
        assert!(notice.id()["wordfence-notice-sha256:".len()..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
    }

    #[test]
    fn source_identity_is_preserved_and_casefolding_is_only_a_qualified_candidate() {
        let mut document: Value = serde_json::from_slice(FIXTURE).unwrap();
        document[FIRST_ID]["software"][0]["slug"] =
            Value::String("Termivar-Fixture-Component".to_owned());
        let encoded = serde_json::to_vec(&document).unwrap();
        let import = parse_wordfence_v3_production(encoded.as_slice()).unwrap();
        assert_eq!(import.mapping_revision(), WORDFENCE_V3_MAPPING_REVISION_V2);
        assert_eq!(import.identity_counts().exact(), 2);
        assert_eq!(import.identity_counts().candidate(), 1);
        assert_eq!(import.identity_counts().ambiguous(), 0);
        assert_eq!(import.identity_counts().unresolved(), 0);

        let component = WordPressComponentIdentity::new(
            WordPressComponentKind::Plugin,
            "termivar-fixture-component",
        )
        .unwrap();
        let association = import
            .associations_for(&component)
            .next()
            .unwrap()
            .association();
        assert_eq!(
            association.source_component().slug(),
            "Termivar-Fixture-Component"
        );
        assert_eq!(
            association.identity_mapping(),
            WordfenceV3IdentityMapping::AsciiCaseFoldCandidate
        );
        assert_eq!(association.identity_collision_raw_count(), None);
    }

    #[test]
    fn casefold_collisions_are_ambiguous_without_corrupting_exact_or_cross_kind_identity() {
        let mut document: Value = serde_json::from_slice(FIXTURE).unwrap();
        let original = document[FIRST_ID]["software"][0].clone();
        document[FIRST_ID]["software"][0]["slug"] =
            Value::String("Termivar-Fixture-Component".to_owned());
        let mut second = original;
        second["slug"] = Value::String("TERMIVAR-FIXTURE-COMPONENT".to_owned());
        document[FIRST_ID]["software"]
            .as_array_mut()
            .unwrap()
            .push(second);
        let encoded = serde_json::to_vec(&document).unwrap();
        let import = parse_wordfence_v3_production(encoded.as_slice()).unwrap();
        assert_eq!(import.identity_counts().exact(), 2);
        assert_eq!(import.identity_counts().candidate(), 0);
        assert_eq!(import.identity_counts().ambiguous(), 2);
        assert_eq!(import.identity_counts().unresolved(), 0);

        let plugin = WordPressComponentIdentity::new(
            WordPressComponentKind::Plugin,
            "termivar-fixture-component",
        )
        .unwrap();
        let plugin_associations = import.associations_for(&plugin).collect::<Vec<_>>();
        assert_eq!(plugin_associations.len(), 2);
        assert!(plugin_associations.iter().all(|view| {
            view.association().identity_mapping()
                == WordfenceV3IdentityMapping::AsciiCaseFoldAmbiguous
                && view.association().identity_collision_raw_count() == Some(2)
        }));

        let theme = WordPressComponentIdentity::new(
            WordPressComponentKind::Theme,
            "termivar-fixture-component",
        )
        .unwrap();
        assert_eq!(
            import
                .associations_for(&theme)
                .next()
                .unwrap()
                .association()
                .identity_mapping(),
            WordfenceV3IdentityMapping::Exact
        );
    }

    #[test]
    fn exact_spelling_remains_exact_while_a_case_variant_is_ambiguous() {
        let mut document: Value = serde_json::from_slice(FIXTURE).unwrap();
        let mut case_variant = document[FIRST_ID]["software"][0].clone();
        case_variant["slug"] = Value::String("Termivar-Fixture-Component".to_owned());
        document[FIRST_ID]["software"]
            .as_array_mut()
            .unwrap()
            .push(case_variant);
        let encoded = serde_json::to_vec(&document).unwrap();
        let import = parse_wordfence_v3_production(encoded.as_slice()).unwrap();
        assert_eq!(import.identity_counts().exact(), 3);
        assert_eq!(import.identity_counts().candidate(), 0);
        assert_eq!(import.identity_counts().ambiguous(), 1);
        let component = WordPressComponentIdentity::new(
            WordPressComponentKind::Plugin,
            "termivar-fixture-component",
        )
        .unwrap();
        let associations = import.associations_for(&component).collect::<Vec<_>>();
        assert_eq!(associations.len(), 2);
        assert_eq!(
            associations
                .iter()
                .filter(|view| view.association().identity_mapping()
                    == WordfenceV3IdentityMapping::Exact)
                .count(),
            1
        );
        let ambiguous = associations
            .iter()
            .find(|view| {
                view.association().identity_mapping()
                    == WordfenceV3IdentityMapping::AsciiCaseFoldAmbiguous
            })
            .unwrap();
        assert_eq!(
            ambiguous.association().identity_collision_raw_count(),
            Some(2)
        );
    }

    #[test]
    fn duplicate_source_association_inside_one_record_fails_closed() {
        let mut document: Value = serde_json::from_slice(FIXTURE).unwrap();
        let duplicate = document[FIRST_ID]["software"][0].clone();
        document[FIRST_ID]["software"]
            .as_array_mut()
            .unwrap()
            .push(duplicate);
        let encoded = serde_json::to_vec(&document).unwrap();
        assert_eq!(
            parse_wordfence_v3_production(encoded.as_slice()),
            Err(WordfenceV3ProductionError::ConflictingIdentity)
        );
    }

    #[test]
    fn distinct_source_association_variants_are_preserved_and_order_independent() {
        let mut document: Value = serde_json::from_slice(FIXTURE).unwrap();
        let mut variant = document[FIRST_ID]["software"][0].clone();
        variant["name"] = Value::String("Synthetic alternate source declaration".to_owned());
        document[FIRST_ID]["software"]
            .as_array_mut()
            .unwrap()
            .push(variant);
        let encoded = serde_json::to_vec(&document).unwrap();
        let original = parse_wordfence_v3_production(encoded.as_slice()).unwrap();

        assert_eq!(original.software_association_count(), 4);
        assert_eq!(
            original.mapping_revision(),
            "termivar-wordfence-v3-production/v1"
        );
        assert_eq!(
            original.resource_policy(),
            "termivar.wordfence-v3-bounded-capacity/v2"
        );
        let record = original
            .records()
            .iter()
            .find(|record| record.upstream_id() == FIRST_ID)
            .unwrap();
        let variants = record
            .software()
            .iter()
            .filter(|association| {
                association.source_component().kind() == WordPressComponentKind::Plugin
                    && association.source_component().slug() == "termivar-fixture-component"
            })
            .collect::<Vec<_>>();
        assert_eq!(variants.len(), 2);
        assert_ne!(
            variants[0].key().source_association_sha256(),
            variants[1].key().source_association_sha256()
        );

        document[FIRST_ID]["software"]
            .as_array_mut()
            .unwrap()
            .reverse();
        let reordered_bytes = serde_json::to_vec_pretty(&document).unwrap();
        let reordered = parse_wordfence_v3_production(reordered_bytes.as_slice()).unwrap();
        assert_ne!(original.sha256(), reordered.sha256());
        assert_eq!(original.semantic_sha256(), reordered.semantic_sha256());
        assert_eq!(original.records(), reordered.records());
    }

    #[test]
    fn safe_opaque_but_unmappable_source_identity_is_retained_and_not_indexed() {
        let mut document: Value = serde_json::from_slice(FIXTURE).unwrap();
        document[FIRST_ID]["software"][0]["slug"] =
            Value::String("https://Example.invalid/plugin_name".to_owned());
        let encoded = serde_json::to_vec(&document).unwrap();
        let import = parse_wordfence_v3_production(encoded.as_slice()).unwrap();
        assert_eq!(import.software_association_count(), 3);
        assert_eq!(import.identity_counts().exact(), 2);
        assert_eq!(import.identity_counts().candidate(), 0);
        assert_eq!(import.identity_counts().ambiguous(), 0);
        assert_eq!(import.identity_counts().unresolved(), 1);
        let record = import
            .records()
            .iter()
            .find(|record| record.upstream_id() == FIRST_ID)
            .unwrap();
        assert_eq!(record.software().len(), 1);
        assert_eq!(record.unresolved_software().len(), 1);
        assert_eq!(
            record.unresolved_software()[0].source_component().slug(),
            "https://Example.invalid/plugin_name"
        );
        let canonical = WordPressComponentIdentity::new(
            WordPressComponentKind::Plugin,
            "termivar-fixture-component",
        )
        .unwrap();
        assert_eq!(import.associations_for(&canonical).count(), 0);
    }

    #[test]
    fn source_identity_controls_non_ascii_and_oversize_values_fail_closed() {
        for source_slug in [
            "bad\nslug".to_owned(),
            "mötley-plugin".to_owned(),
            "...".to_owned(),
            "x".repeat(MAX_WORDFENCE_V3_SOURCE_SLUG_BYTES + 1),
        ] {
            let mut document: Value = serde_json::from_slice(FIXTURE).unwrap();
            document[FIRST_ID]["software"][0]["slug"] = Value::String(source_slug);
            let encoded = serde_json::to_vec(&document).unwrap();
            assert_eq!(
                parse_wordfence_v3_production(encoded.as_slice()),
                Err(WordfenceV3ProductionError::UnsupportedValue)
            );
        }
    }

    #[test]
    fn semantic_digest_ignores_root_record_order_and_json_layout_but_exact_digest_does_not() {
        let original = parse_wordfence_v3_production(FIXTURE).unwrap();
        let value: Value = serde_json::from_slice(FIXTURE).unwrap();
        let object = value.as_object().unwrap();
        let reordered = format!(
            "{{\n  {second:?}: {},\n  {first:?}: {}\n}}",
            serde_json::to_string(&object[SECOND_ID]).unwrap(),
            serde_json::to_string(&object[FIRST_ID]).unwrap(),
            second = SECOND_ID,
            first = FIRST_ID,
        );
        let reordered = parse_wordfence_v3_production(reordered.as_bytes()).unwrap();
        assert_ne!(original.sha256(), reordered.sha256());
        assert_eq!(original.semantic_sha256(), reordered.semantic_sha256());
        assert_eq!(original.records(), reordered.records());
    }

    #[test]
    fn semantic_digest_does_not_change_when_layout_alone_selects_the_larger_resource_envelope() {
        let value: Value = serde_json::from_slice(FIXTURE).unwrap();
        let record = serde_json::to_string(&value[FIRST_ID]).unwrap();
        let compact_document = format!("{{{FIRST_ID:?}:{record}}}");
        let compact = parse_wordfence_v3_production(compact_document.as_bytes()).unwrap();
        assert_eq!(compact.resource_policy(), WORDFENCE_V3_RESOURCE_POLICY_V1);

        let padding_bytes = (MAX_WORDFENCE_V3_RECORD_BYTES_V1 + 1)
            .checked_sub(record.len())
            .expect("fixture record remains below the historical envelope");
        let padded_record = record.replacen('{', &format!("{{{}", " ".repeat(padding_bytes)), 1);
        assert_eq!(padded_record.len(), MAX_WORDFENCE_V3_RECORD_BYTES_V1 + 1);
        let padded_document = format!("{{{FIRST_ID:?}:{padded_record}}}");
        let padded = parse_wordfence_v3_production(padded_document.as_bytes()).unwrap();

        assert_eq!(padded.resource_policy(), WORDFENCE_V3_RESOURCE_POLICY_V2);
        assert_ne!(compact.sha256(), padded.sha256());
        assert_eq!(compact.records(), padded.records());
        assert_eq!(compact.semantic_sha256(), padded.semantic_sha256());
    }

    #[test]
    fn resource_policy_records_the_largest_import_phase_without_rewriting_old_envelopes() {
        assert_eq!(
            resource_policy_for_import(false, MAX_WORDFENCE_V3_RETAINED_BYTES_V1, 1),
            WORDFENCE_V3_RESOURCE_POLICY_V1
        );
        assert_eq!(
            resource_policy_for_import(false, MAX_WORDFENCE_V3_RETAINED_BYTES_V1 + 1, 1,),
            WORDFENCE_V3_RESOURCE_POLICY_V2
        );
        assert_eq!(
            resource_policy_for_import(true, 1, 1),
            WORDFENCE_V3_RESOURCE_POLICY_V2
        );
        assert_eq!(
            resource_policy_for_import(
                false,
                MAX_WORDFENCE_V3_RETAINED_BYTES_V2,
                MAX_WORDFENCE_V3_RETAINED_BYTES_V1,
            ),
            WORDFENCE_V3_RESOURCE_POLICY_V2
        );
        assert_eq!(
            resource_policy_for_import(false, MAX_WORDFENCE_V3_RETAINED_BYTES_V2 + 1, 1,),
            WORDFENCE_V3_RESOURCE_POLICY_V3
        );
        assert_eq!(
            resource_policy_for_import(false, 1, MAX_WORDFENCE_V3_RETAINED_BYTES_V2 + 1,),
            WORDFENCE_V3_RESOURCE_POLICY_V3
        );
    }

    #[test]
    fn vector_growth_is_rejected_before_crossing_the_retained_budget() {
        let mut refused = Vec::<u64>::new();
        let mut no_capacity_budget = RetainedBudget::with_base(0, 0).unwrap();
        assert_eq!(
            reserve_one_with_retained_accounting(&mut refused, &mut no_capacity_budget),
            Err(WordfenceV3ProductionError::RetainedDataTooLarge)
        );
        assert_eq!(refused.capacity(), 0);

        let initial_bytes = 4 * size_of::<u64>();
        let mut bounded = Vec::<u64>::new();
        let mut fixed_budget = RetainedBudget::with_base(initial_bytes, 0).unwrap();
        reserve_one_with_retained_accounting(&mut bounded, &mut fixed_budget).unwrap();
        let initial_capacity = bounded.capacity();
        assert_eq!(initial_capacity, 4);
        bounded.resize(initial_capacity, 0);
        assert_eq!(
            reserve_one_with_retained_accounting(&mut bounded, &mut fixed_budget),
            Err(WordfenceV3ProductionError::RetainedDataTooLarge)
        );
        assert_eq!(bounded.capacity(), initial_capacity);
    }

    #[test]
    fn duplicate_decoded_root_nested_range_and_notice_keys_fail_closed() {
        let value: Value = serde_json::from_slice(FIXTURE).unwrap();
        let record = serde_json::to_string(&value[FIRST_ID]).unwrap();
        let escaped_id = format!("\\u0030{}", &FIRST_ID[1..]);
        let duplicate_root = format!("{{{FIRST_ID:?}:{record},\"{escaped_id}\":{record}}}");
        assert_eq!(
            parse_wordfence_v3_production(duplicate_root.as_bytes()),
            Err(WordfenceV3ProductionError::DuplicateKey)
        );

        let fixture = String::from_utf8(FIXTURE.to_vec()).unwrap();
        let duplicate_range = fixture.replacen(
            r#""from_version": "1.0.0""#,
            r#""from_version": "1.0.0", "from_version": "1.0.0""#,
            1,
        );
        assert_eq!(
            parse_wordfence_v3_production(duplicate_range.as_bytes()),
            Err(WordfenceV3ProductionError::DuplicateKey)
        );
        let duplicate_notice = fixture.replacen(
            r#""message": "This is an original synthetic fixture notice, not a provider notice.""#,
            r#""message": "This is an original synthetic fixture notice, not a provider notice.", "message": "duplicate""#,
            1,
        );
        assert_eq!(
            parse_wordfence_v3_production(duplicate_notice.as_bytes()),
            Err(WordfenceV3ProductionError::DuplicateKey)
        );
    }

    #[test]
    fn key_mismatch_unknown_fields_and_trailing_json_are_rejected() {
        let fixture = String::from_utf8(FIXTURE.to_vec()).unwrap();
        let mismatch = fixture.replacen(FIRST_ID, "10000000-0000-4000-8000-000000000001", 1);
        assert_eq!(
            parse_wordfence_v3_production(mismatch.as_bytes()),
            Err(WordfenceV3ProductionError::ConflictingIdentity)
        );
        let unknown = fixture.replacen(
            r#""informational": false,"#,
            r#""informational": false, "executable_predicate": "never","#,
            1,
        );
        assert_eq!(
            parse_wordfence_v3_production(unknown.as_bytes()),
            Err(WordfenceV3ProductionError::UnsupportedValue)
        );
        let trailing = format!("{fixture} true");
        assert_eq!(
            parse_wordfence_v3_production(trailing.as_bytes()),
            Err(WordfenceV3ProductionError::MalformedJson)
        );
    }

    #[test]
    fn unknown_nested_software_range_cwe_cvss_and_notice_fields_fail_closed() {
        let fixture = String::from_utf8(FIXTURE.to_vec()).unwrap();
        for (location, needle, replacement) in [
            (
                "software",
                r#""slug": "termivar-fixture-component","#,
                r#""slug": "termivar-fixture-component", "future_software_field": true,"#,
            ),
            (
                "affected range",
                r#""from_version": "1.0.0","#,
                r#""from_version": "1.0.0", "future_range_field": true,"#,
            ),
            (
                "CWE",
                r#""id": 9999,"#,
                r#""id": 9999, "future_cwe_field": true,"#,
            ),
            (
                "CVSS",
                r#""vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N","#,
                r#""vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "future_cvss_field": true,"#,
            ),
            (
                "notice party",
                r#""notice": "Synthetic fixture material created for Termivar parser testing.","#,
                r#""notice": "Synthetic fixture material created for Termivar parser testing.", "future_notice_field": true,"#,
            ),
        ] {
            let document = fixture.replacen(needle, replacement, 1);
            assert_ne!(document, fixture, "test mutation missed {location}");
            assert_eq!(
                parse_wordfence_v3_production(document.as_bytes()),
                Err(WordfenceV3ProductionError::UnsupportedValue),
                "unknown {location} field must not be silently discarded"
            );
        }
    }

    #[test]
    fn truncated_root_key_record_and_final_object_are_rejected_as_malformed() {
        let first_key = FIXTURE
            .windows(FIRST_ID.len())
            .position(|window| window == FIRST_ID.as_bytes())
            .unwrap();
        let first_software = FIXTURE
            .windows(b"\"software\"".len())
            .position(|window| window == b"\"software\"")
            .unwrap();
        let final_close = FIXTURE.iter().rposition(|byte| *byte == b'}').unwrap();
        for (location, end) in [
            ("root opener", 1),
            ("root key", first_key + 7),
            ("record", first_software + 6),
            ("middle", FIXTURE.len() / 2),
            ("final object", final_close),
        ] {
            assert_eq!(
                parse_wordfence_v3_production(&FIXTURE[..end]),
                Err(WordfenceV3ProductionError::MalformedJson),
                "truncation at {location} must not be accepted as a prefix"
            );
        }
    }

    #[test]
    fn wildcard_is_exact_and_source_versions_are_not_interpreted_by_the_parser() {
        let import = parse_wordfence_v3_production(FIXTURE).unwrap();
        let theme = WordPressComponentIdentity::new(
            WordPressComponentKind::Theme,
            "termivar-fixture-component",
        )
        .unwrap();
        assert!(matches!(
            import
                .associations_for(&theme)
                .next()
                .unwrap()
                .association()
                .affected_ranges()[0]
                .from()
                .value(),
            WordfenceV3RangeValue::Any
        ));

        let literal = String::from_utf8(FIXTURE.to_vec()).unwrap().replacen(
            r#""from_version": "*""#,
            r#""from_version": "1.*""#,
            1,
        );
        let import = parse_wordfence_v3_production(literal.as_bytes()).unwrap();
        assert!(matches!(
            import
                .associations_for(&theme)
                .next()
                .unwrap()
                .association()
                .affected_ranges()[0]
                .from()
                .value(),
            WordfenceV3RangeValue::Declared(value) if value == "1.*"
        ));

        let opaque_version = "44.0 (17-08-2023)";
        let opaque_unicode_version = "0.1.2 β";
        let plugin = WordPressComponentIdentity::new(
            WordPressComponentKind::Plugin,
            "termivar-fixture-component",
        )
        .unwrap();
        let mut document: Value = serde_json::from_slice(FIXTURE).unwrap();
        document[FIRST_ID]["software"][0]["affected_versions"]["[1.0.0, 1.2.3]"]["to_version"] =
            Value::String(opaque_unicode_version.to_owned());
        document[FIRST_ID]["software"][0]["patched_versions"] =
            Value::Array(vec![Value::String(opaque_version.to_owned())]);
        let encoded = serde_json::to_vec(&document).unwrap();
        let import = parse_wordfence_v3_production(encoded.as_slice()).unwrap();
        assert_eq!(import.resource_policy(), WORDFENCE_V3_RESOURCE_POLICY_V2);
        let association = import
            .associations_for(&plugin)
            .next()
            .unwrap()
            .association();
        let changed_range = association
            .affected_ranges()
            .iter()
            .find(|range| range.label() == "[1.0.0, 1.2.3]")
            .expect("changed source range remains present");
        assert!(matches!(
            changed_range.to().value(),
            WordfenceV3RangeValue::Declared(value) if value == opaque_unicode_version
        ));
        assert_eq!(association.patched_versions(), [opaque_version]);

        for invalid in [" leading", "trailing ", "embedded\tcontrol"] {
            let mut document: Value = serde_json::from_slice(FIXTURE).unwrap();
            document[FIRST_ID]["software"][0]["patched_versions"] =
                Value::Array(vec![Value::String(invalid.to_owned())]);
            let encoded = serde_json::to_vec(&document).unwrap();
            assert_eq!(
                parse_wordfence_v3_production(encoded.as_slice()),
                Err(WordfenceV3ProductionError::UnsupportedValue)
            );
        }
    }

    #[test]
    fn repeated_researcher_attribution_is_preserved_without_becoming_an_identity_conflict() {
        let mut document: Value = serde_json::from_slice(FIXTURE).unwrap();
        document[FIRST_ID]["researchers"] = serde_json::json!(["Researcher", "Researcher"]);
        let encoded = serde_json::to_vec(&document).unwrap();
        let import = parse_wordfence_v3_production(encoded.as_slice()).unwrap();
        let record = import
            .records()
            .iter()
            .find(|record| record.upstream_id() == FIRST_ID)
            .unwrap();
        assert_eq!(record.researchers(), ["Researcher", "Researcher"]);
        assert_eq!(import.resource_policy(), WORDFENCE_V3_RESOURCE_POLICY_V2);
    }

    #[test]
    fn invalid_dates_cvss_bounds_and_executable_or_credentialed_urls_are_rejected() {
        let fixture = String::from_utf8(FIXTURE.to_vec()).unwrap();
        for invalid in [
            fixture.replacen("2026-01-02 03:04:05", "2026-13-02 03:04:05", 1),
            fixture.replacen("2026-01-02 03:04:05", "2026-02-30 03:04:05", 1),
            fixture.replacen(r#""score": 5.3"#, r#""score": 5.33"#, 1),
            fixture.replacen(r#""score": 5.3"#, r#""score": 10.1"#, 1),
            fixture.replacen(
                "https://example.invalid/termivar/wordfence-v3/fixture-advisory-1",
                "javascript:alert(1)",
                1,
            ),
            fixture.replacen(
                "https://example.invalid/termivar/wordfence-v3/synthetic-fixture-terms",
                "https://user:secret@example.invalid/terms",
                1,
            ),
        ] {
            assert_eq!(
                parse_wordfence_v3_production(invalid.as_bytes()),
                Err(WordfenceV3ProductionError::UnsupportedValue)
            );
        }
    }

    #[test]
    fn defiant_notice_requires_an_exact_official_record_reference_at_preflight() {
        for reference in [
            "http://www.wordfence.com/threat-intel/vulnerabilities/synthetic-fixture",
            "https://www.wordfence.com/threat-intel/vulnerabilities/synthetic-fixture",
            "https://www.wordfence.com/threat-intel/vulnerabilities/synthetic-fixture?source=api-test",
        ] {
            let document = document_with_defiant_reference(Some(reference));
            assert!(parse_wordfence_v3_production(document.as_slice()).is_ok());
        }

        for reference in [
            None,
            Some("https://wordfence.com/threat-intel/vulnerabilities/synthetic-fixture"),
            Some("https://www.wordfence.com/help/synthetic-fixture"),
            Some("https://www.wordfence.com/threat-intel/vulnerabilities/"),
            Some("https://www.wordfence.com:8443/threat-intel/vulnerabilities/synthetic-fixture"),
            Some("https://www.wordfence.com/threat-intel/vulnerabilities/synthetic-fixture?q=1"),
            Some("https://www.wordfence.com/threat-intel/vulnerabilities/synthetic-fixture?source"),
            Some("https://www.wordfence.com/threat-intel/vulnerabilities/synthetic-fixture?source="),
            Some("https://www.wordfence.com/threat-intel/vulnerabilities/synthetic-fixture?source=api-test&source=other"),
            Some("https://www.wordfence.com/threat-intel/vulnerabilities/synthetic-fixture?source=api-test&extra=1"),
            Some("https://www.wordfence.com/threat-intel/vulnerabilities/synthetic-fixture?other=api-test"),
            Some("https://www.wordfence.com/threat-intel/vulnerabilities/synthetic-fixture?source=api%2Dtest"),
            Some("https://www.wordfence.com/threat-intel/vulnerabilities/synthetic-fixture?source=api+test"),
            Some("https://www.wordfence.com/threat-intel/vulnerabilities/synthetic-fixture?source=api-test#part"),
            Some("https://www.wordfence.com/threat-intel/vulnerabilities/synthetic-fixture#part"),
        ] {
            let document = document_with_defiant_reference(reference);
            assert_eq!(
                parse_wordfence_v3_production(document.as_slice()),
                Err(WordfenceV3ProductionError::UnsupportedValue)
            );
        }

        let oversized_source = format!(
            "https://www.wordfence.com/threat-intel/vulnerabilities/synthetic-fixture?source={}",
            "a".repeat(65)
        );
        let document = document_with_defiant_reference(Some(&oversized_source));
        assert_eq!(
            parse_wordfence_v3_production(document.as_slice()),
            Err(WordfenceV3ProductionError::UnsupportedValue)
        );

        let maximum_source = format!(
            "https://www.wordfence.com/threat-intel/vulnerabilities/synthetic-fixture?source={}",
            "a".repeat(64)
        );
        let document = document_with_defiant_reference(Some(&maximum_source));
        assert!(parse_wordfence_v3_production(document.as_slice()).is_ok());
    }

    #[test]
    fn equivalent_json_number_spellings_use_one_reader_compatible_cvss_projection() {
        let fixture = String::from_utf8(FIXTURE.to_vec()).unwrap();
        for (spelling, expected) in [("5.30", "5.3"), ("1e0", "1.0")] {
            let document =
                fixture.replacen(r#""score": 5.3"#, &format!(r#""score": {spelling}"#), 1);
            let import = parse_wordfence_v3_production(document.as_bytes()).unwrap();
            assert_eq!(import.records()[0].cvss().unwrap().score(), expected);
        }
    }

    #[test]
    fn nullable_cve_link_relation_lowercase_ids_and_empty_source_ranges_are_explicit() {
        let fixture = String::from_utf8(FIXTURE.to_vec()).unwrap();
        let cve_without_link = fixture.replacen(r#""cve": null"#, r#""cve": "CVE-2026-12345""#, 1);
        assert!(parse_wordfence_v3_production(cve_without_link.as_bytes()).is_ok());

        let link_without_cve = fixture.replacen(
            r#""cve_link": null"#,
            r#""cve_link": "https://www.cve.org/CVERecord?id=CVE-2026-12345""#,
            1,
        );
        assert_eq!(
            parse_wordfence_v3_production(link_without_cve.as_bytes()),
            Err(WordfenceV3ProductionError::ConflictingIdentity)
        );

        let uppercase_id = fixture.replacen(FIRST_ID, "ABCDEFAB-CDEF-4ABC-8DEF-ABCDEFABCDEF", 2);
        assert_eq!(
            parse_wordfence_v3_production(uppercase_id.as_bytes()),
            Err(WordfenceV3ProductionError::UnsupportedValue)
        );

        let mut no_ranges: Value = serde_json::from_slice(FIXTURE).unwrap();
        no_ranges[FIRST_ID]["software"][0]["affected_versions"] =
            Value::Object(serde_json::Map::new());
        let no_ranges = serde_json::to_vec(&no_ranges).unwrap();
        let import = parse_wordfence_v3_production(no_ranges.as_slice()).unwrap();
        let plugin = WordPressComponentIdentity::new(
            WordPressComponentKind::Plugin,
            "termivar-fixture-component",
        )
        .unwrap();
        assert!(import
            .associations_for(&plugin)
            .next()
            .unwrap()
            .association()
            .affected_ranges()
            .is_empty());
    }

    #[test]
    fn external_record_limits_admit_the_documented_range_and_label_boundaries() {
        let maximum_ranges = document_with_range_labels(
            (0..MAX_WORDFENCE_V3_RANGES_PER_ASSOCIATION).map(|index| format!("range-{index:02}")),
        );
        let import = parse_wordfence_v3_production(maximum_ranges.as_slice()).unwrap();
        assert_eq!(
            import.records()[0].software()[0].affected_ranges().len(),
            MAX_WORDFENCE_V3_RANGES_PER_ASSOCIATION
        );
        assert_eq!(import.resource_policy(), WORDFENCE_V3_RESOURCE_POLICY_V2);

        let excessive_ranges = document_with_range_labels(
            (0..=MAX_WORDFENCE_V3_RANGES_PER_ASSOCIATION).map(|index| format!("range-{index:02}")),
        );
        assert_eq!(
            parse_wordfence_v3_production(excessive_ranges.as_slice()),
            Err(WordfenceV3ProductionError::StructuralLimitExceeded)
        );

        let seventy_eight = document_with_range_and_patch_counts(78, 78);
        let import = parse_wordfence_v3_production(seventy_eight.as_slice()).unwrap();
        let association = &import.records()[0].software()[0];
        assert_eq!(association.affected_ranges().len(), 78);
        assert_eq!(association.patched_versions().len(), 78);

        let maximum_patches =
            document_with_range_and_patch_counts(1, MAX_WORDFENCE_V3_PATCHED_VERSIONS);
        assert!(parse_wordfence_v3_production(maximum_patches.as_slice()).is_ok());
        let excessive_patches =
            document_with_range_and_patch_counts(1, MAX_WORDFENCE_V3_PATCHED_VERSIONS + 1);
        assert_eq!(
            parse_wordfence_v3_production(excessive_patches.as_slice()),
            Err(WordfenceV3ProductionError::StructuralLimitExceeded)
        );

        let maximum_label =
            document_with_range_labels(["x".repeat(MAX_WORDFENCE_V3_RANGE_LABEL_BYTES)]);
        assert!(parse_wordfence_v3_production(maximum_label.as_slice()).is_ok());

        let oversized_label =
            document_with_range_labels(["x".repeat(MAX_WORDFENCE_V3_RANGE_LABEL_BYTES + 1)]);
        assert_eq!(
            parse_wordfence_v3_production(oversized_label.as_slice()),
            Err(WordfenceV3ProductionError::StructuralLimitExceeded)
        );
    }

    #[test]
    fn expanded_description_and_record_limits_have_finite_new_boundaries() {
        let fixture = String::from_utf8(FIXTURE.to_vec()).unwrap();
        let original_description =
            "Fictional prose created only to exercise bounded Production-format ingestion. It is not a vulnerability claim.";
        let formerly_excessive = fixture.replacen(
            original_description,
            &"d".repeat(MAX_WORDFENCE_V3_DESCRIPTION_BYTES_V1 + 1),
            1,
        );
        let import = parse_wordfence_v3_production(formerly_excessive.as_bytes()).unwrap();
        assert_eq!(import.resource_policy(), WORDFENCE_V3_RESOURCE_POLICY_V2);

        let maximum_description = fixture.replacen(
            original_description,
            &"d".repeat(MAX_WORDFENCE_V3_DESCRIPTION_BYTES),
            1,
        );
        assert!(parse_wordfence_v3_production(maximum_description.as_bytes()).is_ok());
        let excessive_description = fixture.replacen(
            original_description,
            &"d".repeat(MAX_WORDFENCE_V3_DESCRIPTION_BYTES + 1),
            1,
        );
        assert_eq!(
            parse_wordfence_v3_production(excessive_description.as_bytes()),
            Err(WordfenceV3ProductionError::StructuralLimitExceeded)
        );

        let expanded_record = document_between_record_limits();
        assert!(expanded_record.len() > MAX_WORDFENCE_V3_RECORD_BYTES_V1);
        assert!(expanded_record.len() <= MAX_WORDFENCE_V3_RECORD_BYTES);
        let import = parse_wordfence_v3_production(expanded_record.as_slice()).unwrap();
        assert_eq!(import.resource_policy(), WORDFENCE_V3_RESOURCE_POLICY_V2);
    }

    #[test]
    fn retained_budget_stops_streaming_before_unread_records() {
        let observed = std::rc::Rc::new(std::cell::Cell::new(0));
        let reader = OneByteCountingReader {
            bytes: FIXTURE,
            position: 0,
            observed: std::rc::Rc::clone(&observed),
        };
        // This permits the import header and first root identity but not the
        // first decoded record/notices. It exercises the production parser's
        // incremental retained-data guard without allocating 64 MiB in a test.
        let retained_limit = size_of::<WordfenceV3ProductionImport>() + 512;
        assert_eq!(
            parse_wordfence_v3_production_with_limits(reader, FIXTURE.len(), retained_limit),
            Err(WordfenceV3ProductionError::RetainedDataTooLarge)
        );
        let second_record_offset = FIXTURE
            .windows(SECOND_ID.len())
            .position(|window| window == SECOND_ID.as_bytes())
            .unwrap();
        assert!(
            observed.get() < second_record_offset,
            "the retained-data guard must stop before reading the second record"
        );
    }

    #[test]
    fn vector_growth_is_amortized_and_charges_actual_capacity_deltas() {
        fn assert_growth_contract<T: Clone>(value: T) {
            let mut values = Vec::new();
            let mut retained = RetainedBudget::with_base(usize::MAX, 0).unwrap();
            let mut growth_events = 0_usize;
            for _ in 0..128 {
                let previous_capacity = values.capacity();
                let previous_retained = retained.total();
                reserve_one_with_retained_accounting(&mut values, &mut retained).unwrap();
                let capacity_delta = values.capacity() - previous_capacity;
                if capacity_delta != 0 {
                    growth_events += 1;
                }
                assert_eq!(
                    retained.total() - previous_retained,
                    capacity_delta * size_of::<T>()
                );
                values.push(value.clone());
                assert_eq!(retained.total(), values.capacity() * size_of::<T>());
            }
            assert!(
                growth_events < values.len(),
                "reserve-one growth must not reallocate for every pushed item"
            );
        }

        assert_growth_contract((0_usize, 0_usize));
        let import = parse_wordfence_v3_production(FIXTURE).unwrap();
        assert_growth_contract(import.records()[0].clone());
    }

    fn document_with_range_labels(labels: impl IntoIterator<Item = String>) -> Vec<u8> {
        let mut document: Value = serde_json::from_slice(FIXTURE).unwrap();
        let template =
            document[FIRST_ID]["software"][0]["affected_versions"]["[1.0.0, 1.2.3]"].clone();
        let ranges = labels
            .into_iter()
            .map(|label| (label, template.clone()))
            .collect::<serde_json::Map<_, _>>();
        document[FIRST_ID]["software"][0]["affected_versions"] = Value::Object(ranges);
        serde_json::to_vec(&document).unwrap()
    }

    fn document_with_range_and_patch_counts(range_count: usize, patch_count: usize) -> Vec<u8> {
        let mut document: Value = serde_json::from_slice(FIXTURE).unwrap();
        let template =
            document[FIRST_ID]["software"][0]["affected_versions"]["[1.0.0, 1.2.3]"].clone();
        document[FIRST_ID]["software"][0]["affected_versions"] = Value::Object(
            (0..range_count)
                .map(|index| (format!("range-{index:03}"), template.clone()))
                .collect(),
        );
        document[FIRST_ID]["software"][0]["patched_versions"] = Value::Array(
            (0..patch_count)
                .map(|index| Value::String(format!("1.0.{index}")))
                .collect(),
        );
        serde_json::to_vec(&document).unwrap()
    }

    fn document_between_record_limits() -> Vec<u8> {
        let mut document: Value = serde_json::from_slice(FIXTURE).unwrap();
        document.as_object_mut().unwrap().remove(SECOND_ID);
        let mut template = document[FIRST_ID]["software"][0].clone();
        template["name"] = Value::String("n".repeat(128));
        template["remediation"] = Value::String("r".repeat(600));
        let software = (0..600)
            .map(|index| {
                let mut association = template.clone();
                association["slug"] = Value::String(format!("termivar-capacity-{index:04}"));
                association
            })
            .collect();
        document[FIRST_ID]["software"] = Value::Array(software);
        serde_json::to_vec(&document).unwrap()
    }

    fn document_with_defiant_reference(reference: Option<&str>) -> Vec<u8> {
        let mut document: Value = serde_json::from_slice(FIXTURE).unwrap();
        let copyrights = document[FIRST_ID]["copyrights"].as_object_mut().unwrap();
        let notice = copyrights.remove("termivar_fixture_author").unwrap();
        copyrights.insert("defiant".to_owned(), notice);
        document[FIRST_ID]["references"] = Value::Array(
            reference
                .into_iter()
                .map(|value| Value::String(value.to_owned()))
                .collect(),
        );
        serde_json::to_vec(&document).unwrap()
    }

    struct OneByteCountingReader<'a> {
        bytes: &'a [u8],
        position: usize,
        observed: std::rc::Rc<std::cell::Cell<usize>>,
    }

    #[derive(Default)]
    struct DeterministicReadTrace {
        data_reads: usize,
        interrupted_reads: usize,
        eof_reads: usize,
        bytes_returned: usize,
    }

    struct DeterministicChunkReader<'a> {
        bytes: &'a [u8],
        position: usize,
        maximum_chunk: usize,
        interrupt_before_each_result: bool,
        interruption_pending: bool,
        trace: std::rc::Rc<std::cell::RefCell<DeterministicReadTrace>>,
    }

    impl Read for DeterministicChunkReader<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            if buffer.is_empty() {
                return Ok(0);
            }
            if self.interrupt_before_each_result && self.interruption_pending {
                self.interruption_pending = false;
                self.trace.borrow_mut().interrupted_reads += 1;
                return Err(std::io::Error::from(ErrorKind::Interrupted));
            }
            if self.position == self.bytes.len() {
                self.trace.borrow_mut().eof_reads += 1;
                return Ok(0);
            }
            let copied = buffer
                .len()
                .min(self.maximum_chunk)
                .min(self.bytes.len() - self.position);
            buffer[..copied].copy_from_slice(&self.bytes[self.position..self.position + copied]);
            self.position += copied;
            self.interruption_pending = self.interrupt_before_each_result;
            let mut trace = self.trace.borrow_mut();
            trace.data_reads += 1;
            trace.bytes_returned += copied;
            Ok(copied)
        }
    }

    #[test]
    fn one_byte_chunked_and_interrupted_readers_complete_once_through_eof() {
        for (label, maximum_chunk, interrupted) in [
            ("one-byte", 1_usize, false),
            ("chunked", 37, false),
            ("interrupted", 29, true),
        ] {
            let trace =
                std::rc::Rc::new(std::cell::RefCell::new(DeterministicReadTrace::default()));
            let reader = DeterministicChunkReader {
                bytes: FIXTURE,
                position: 0,
                maximum_chunk,
                interrupt_before_each_result: interrupted,
                interruption_pending: interrupted,
                trace: std::rc::Rc::clone(&trace),
            };
            let import = parse_wordfence_v3_production(reader).unwrap();
            assert_eq!(import.byte_length(), FIXTURE.len() as u64, "{label}");
            assert_eq!(import.sha256(), &FIXTURE_SHA256, "{label}");
            assert_eq!(import.record_count(), 2, "{label}");
            assert_eq!(import.software_association_count(), 3, "{label}");
            assert_eq!(import.affected_range_count(), 4, "{label}");

            let trace = trace.borrow();
            let expected_data_reads = FIXTURE.len().div_ceil(maximum_chunk);
            assert_eq!(trace.data_reads, expected_data_reads, "{label}");
            assert_eq!(trace.bytes_returned, FIXTURE.len(), "{label}");
            assert_eq!(trace.eof_reads, 1, "{label}");
            assert_eq!(
                trace.interrupted_reads,
                if interrupted {
                    expected_data_reads + 1
                } else {
                    0
                },
                "{label}"
            );
        }
    }

    impl Read for OneByteCountingReader<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            if buffer.is_empty() || self.position == self.bytes.len() {
                return Ok(0);
            }
            buffer[0] = self.bytes[self.position];
            self.position += 1;
            self.observed.set(self.position);
            Ok(1)
        }
    }

    #[test]
    fn record_retained_and_reader_failures_are_bounded_and_typed() {
        let huge_record = format!(
            "{{{id:?}:{{\"id\":{id:?},\"title\":\"x\",\"software\":[],\"informational\":false,\"description\":\"{}\",\"references\":[],\"cwe\":null,\"cvss\":null,\"cve\":null,\"cve_link\":null,\"researchers\":[],\"published\":null,\"updated\":null,\"copyrights\":null}}}}",
            "x".repeat(MAX_WORDFENCE_V3_RECORD_BYTES),
            id = FIRST_ID,
        );
        assert_eq!(
            parse_wordfence_v3_production(huge_record.as_bytes()),
            Err(WordfenceV3ProductionError::RecordTooLarge)
        );

        let mut retained = RetainedBudget::with_base(
            MAX_WORDFENCE_V3_RETAINED_BYTES,
            MAX_WORDFENCE_V3_RETAINED_BYTES,
        )
        .unwrap();
        assert_eq!(
            retained.add(1),
            Err(WordfenceV3ProductionError::RetainedDataTooLarge)
        );
        assert_eq!(
            parse_wordfence_v3_production(FailingReader { remaining: 8 }),
            Err(WordfenceV3ProductionError::ReadFailed)
        );
        assert_eq!(
            parse_wordfence_v3_production(&b""[..]),
            Err(WordfenceV3ProductionError::EmptyInput)
        );
    }

    struct FailingReader {
        remaining: usize,
    }

    impl Read for FailingReader {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            if self.remaining == 0 {
                return Err(std::io::Error::other("synthetic read failure"));
            }
            let copied = buffer.len().min(self.remaining);
            buffer[..copied].fill(b' ');
            self.remaining -= copied;
            Ok(copied)
        }
    }

    #[test]
    fn a_small_cursor_limit_detects_raw_growth_without_allocating_the_public_ceiling() {
        let observed = std::rc::Rc::new(std::cell::Cell::new(0));
        let reader = BulkCountingReader {
            remaining: 1_000,
            observed: std::rc::Rc::clone(&observed),
        };
        let mut cursor = MeasuredCursor::with_limit(reader, 8);
        for _ in 0..8 {
            assert!(cursor.next_byte().unwrap().is_some());
        }
        assert_eq!(
            cursor.next_byte(),
            Err(WordfenceV3ProductionError::InputTooLarge)
        );
        assert_eq!(observed.get(), 9);
        assert_eq!(MAX_WORDFENCE_V3_PRODUCTION_BYTES, 256 * 1024 * 1024);
    }

    struct BulkCountingReader {
        remaining: usize,
        observed: std::rc::Rc<std::cell::Cell<usize>>,
    }

    impl Read for BulkCountingReader {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            let copied = buffer.len().min(self.remaining);
            buffer[..copied].fill(b'x');
            self.remaining -= copied;
            self.observed.set(self.observed.get() + copied);
            Ok(copied)
        }
    }
}
