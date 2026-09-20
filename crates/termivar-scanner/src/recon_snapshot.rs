//! Strict, bounded import of finite offline reconnaissance snapshots.
//!
//! A snapshot is caller-supplied reference material. Parsing computes the
//! identity of the exact input bytes, but it does not authenticate any source
//! declaration, verify collection times or rights, contact a provider or
//! target, decompress an archive, or turn a listed value into a finding. Every
//! returned record remains a source-qualified, unverified hypothesis.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    mem::size_of,
    net::IpAddr,
};

use serde::{
    de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer,
};
use serde_json::{Number, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// The only reconnaissance snapshot schema accepted by this module.
pub const RECONNAISSANCE_SNAPSHOT_SCHEMA: &str = "security.recon-snapshot/v1";
/// Stable parser and interpretation policy applied to the V1 schema.
pub const RECONNAISSANCE_SNAPSHOT_POLICY: &str = "termivar.recon-snapshot-import/v1";
/// Maximum accepted exact input size.
pub const MAX_RECONNAISSANCE_SNAPSHOT_INPUT_BYTES: usize = 1024 * 1024;
/// Concise integration alias for the exact input-size ceiling.
pub const MAX_RECON_SNAPSHOT_BYTES: usize = MAX_RECONNAISSANCE_SNAPSHOT_INPUT_BYTES;
/// Maximum number of declared sources in one snapshot.
pub const MAX_RECONNAISSANCE_SNAPSHOT_SOURCES: usize = 1024;
/// Maximum number of hypothesis records in one snapshot.
pub const MAX_RECONNAISSANCE_SNAPSHOT_RECORDS: usize = 1024;
/// Maximum total record-to-source associations in one snapshot.
pub const MAX_RECONNAISSANCE_SNAPSHOT_SOURCE_ASSOCIATIONS: usize = 4096;
/// Maximum conservative allocation attributed to prepared lookup indexes.
pub const MAX_RECONNAISSANCE_SNAPSHOT_PREPARED_INDEX_BYTES: usize = 4 * 1024 * 1024;

const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_TIMESTAMP_BYTES: usize = 96;
const MAX_ORIGIN_BYTES: usize = 2048;
const MAX_RIGHTS_TEXT_BYTES: usize = 4096;
const MAX_PRODUCT_BYTES: usize = 256;
const MAX_VERSION_BYTES: usize = 128;
const MAX_LABEL_BYTES: usize = 256;
const MAX_DNS_NAME_BYTES: usize = 253;
const MAX_JSON_DEPTH: usize = 16;
const MAX_JSON_NODES: usize = 65_536;
const MAX_JSON_MEMBERS: usize = 32_768;
const MAX_JSON_ARRAY_ITEMS: usize = 8192;
const MAX_JSON_KEY_BYTES: usize = 128;
const MAX_JSON_STRING_BYTES: usize = 4096;
const CONSERVATIVE_BTREE_ENTRY_OVERHEAD: usize = 96;
const DUPLICATE_KEY_MARKER: &str = "termivar_recon_snapshot_duplicate_key";
const JSON_LIMIT_MARKER: &str = "termivar_recon_snapshot_json_limit";

/// Exact identity of the caller-supplied JSON bytes.
///
/// This is deliberately separate from every operator- or provider-declared
/// identifier in the snapshot. It authenticates neither those declarations
/// nor the party that supplied the bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconnaissanceSnapshotInputIdentity {
    byte_length: u64,
    sha256: [u8; 32],
}

impl ReconnaissanceSnapshotInputIdentity {
    /// Returns the length of the exact JSON input.
    #[must_use]
    pub const fn byte_length(&self) -> u64 {
        self.byte_length
    }

    /// Returns SHA-256 over the exact JSON input, including layout and order.
    #[must_use]
    pub const fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }

    /// Returns the exact-input digest as lowercase hexadecimal.
    #[must_use]
    pub fn sha256_hex(&self) -> String {
        hex_digest(self.sha256)
    }
}

/// Fixed interpretation limit attached to every imported record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconnaissanceClaimLimit {
    /// Values remain source-qualified hypotheses and are not findings or
    /// independently verified claims.
    SourceQualifiedHypothesesOnly,
}

impl ReconnaissanceClaimLimit {
    /// Returns the stable reporting token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SourceQualifiedHypothesesOnly => "source_qualified_hypotheses_only",
        }
    }
}

/// Closed status for external work excluded from this offline parser.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconnaissanceExternalOperationStatus {
    /// The operation was not performed.
    NotPerformed,
}

impl ReconnaissanceExternalOperationStatus {
    /// Returns the stable reporting token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotPerformed => "not_performed",
        }
    }
}

/// Proof-of-scope facts for the transport-free, archive-free import.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReconnaissanceExternalActivity;

impl ReconnaissanceExternalActivity {
    /// Target requests made by this parser; fixed at zero.
    #[must_use]
    pub const fn target_request_count(self) -> u8 {
        0
    }

    /// Provider requests made by this parser; fixed at zero.
    #[must_use]
    pub const fn provider_request_count(self) -> u8 {
        0
    }

    /// Archive handling is outside the accepted input contract.
    #[must_use]
    pub const fn archive_processing(self) -> ReconnaissanceExternalOperationStatus {
        ReconnaissanceExternalOperationStatus::NotPerformed
    }

    /// Decompression is outside the accepted input contract.
    #[must_use]
    pub const fn decompression(self) -> ReconnaissanceExternalOperationStatus {
        ReconnaissanceExternalOperationStatus::NotPerformed
    }
}

/// Value-free audit for one successful strict import.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconnaissanceSnapshotAudit {
    input: ReconnaissanceSnapshotInputIdentity,
    source_count: usize,
    record_count: usize,
    source_association_count: usize,
    prepared_index_bytes: usize,
}

impl ReconnaissanceSnapshotAudit {
    /// Returns the accepted wire schema.
    #[must_use]
    pub const fn schema(&self) -> &'static str {
        RECONNAISSANCE_SNAPSHOT_SCHEMA
    }

    /// Returns the parser and interpretation policy.
    #[must_use]
    pub const fn policy(&self) -> &'static str {
        RECONNAISSANCE_SNAPSHOT_POLICY
    }

    /// Returns the exact-input identity, distinct from declared provenance.
    #[must_use]
    pub const fn input(&self) -> &ReconnaissanceSnapshotInputIdentity {
        &self.input
    }

    /// Returns the exact input byte length.
    #[must_use]
    pub const fn input_byte_length(&self) -> u64 {
        self.input.byte_length
    }

    /// Returns SHA-256 over the exact input bytes.
    #[must_use]
    pub const fn input_sha256(&self) -> &[u8; 32] {
        &self.input.sha256
    }

    /// Returns the number of declared sources retained by the import.
    #[must_use]
    pub const fn source_count(&self) -> usize {
        self.source_count
    }

    /// Returns the number of source-qualified hypothesis records.
    #[must_use]
    pub const fn record_count(&self) -> usize {
        self.record_count
    }

    /// Returns the total number of resolved record-to-source associations.
    #[must_use]
    pub const fn source_association_count(&self) -> usize {
        self.source_association_count
    }

    /// Returns conservative bytes charged to the prepared lookup indexes.
    #[must_use]
    pub const fn prepared_index_bytes(&self) -> usize {
        self.prepared_index_bytes
    }

    /// Returns the fixed no-network/no-archive activity facts.
    #[must_use]
    pub const fn external_activity(&self) -> ReconnaissanceExternalActivity {
        ReconnaissanceExternalActivity
    }

    /// Returns the fixed hypothesis-only interpretation boundary.
    #[must_use]
    pub const fn claim_limit(&self) -> ReconnaissanceClaimLimit {
        ReconnaissanceClaimLimit::SourceQualifiedHypothesesOnly
    }
}

/// Completeness asserted by a source declaration.
///
/// No variant is independently verified by this parser.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconnaissanceCompleteness {
    /// The source declares that the supplied material is complete for its own
    /// unspecified provider scope.
    CompleteAsDeclared,
    /// The source declares partial coverage.
    PartialAsDeclared,
    /// Completeness was declared unknown.
    Unknown,
}

impl ReconnaissanceCompleteness {
    /// Returns the V1 wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CompleteAsDeclared => "complete_as_declared",
            Self::PartialAsDeclared => "partial_as_declared",
            Self::Unknown => "unknown",
        }
    }
}

/// Rights status asserted by the snapshot source declaration.
///
/// The parser preserves this statement as inert metadata; it does not verify
/// ownership, licensing, permission, attribution, or redistribution rights.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconnaissanceDeclaredRightsStatus {
    /// The snapshot declares use to be permitted.
    PermittedAsDeclared,
    /// The snapshot declares some restriction.
    RestrictedAsDeclared,
    /// The snapshot declares no known rights status.
    Unknown,
}

impl ReconnaissanceDeclaredRightsStatus {
    /// Returns the V1 wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PermittedAsDeclared => "permitted_as_declared",
            Self::RestrictedAsDeclared => "restricted_as_declared",
            Self::Unknown => "unknown",
        }
    }
}

/// Inert attribution and notice text supplied by a source declaration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconnaissanceDeclaredRights {
    status: ReconnaissanceDeclaredRightsStatus,
    attribution: Option<String>,
    notice: Option<String>,
}

impl ReconnaissanceDeclaredRights {
    /// Returns the unverified declared rights status.
    #[must_use]
    pub const fn status(&self) -> ReconnaissanceDeclaredRightsStatus {
        self.status
    }

    /// Returns inert declared attribution text, if supplied.
    #[must_use]
    pub fn attribution(&self) -> Option<&str> {
        self.attribution.as_deref()
    }

    /// Returns inert declared rights notice text, if supplied.
    #[must_use]
    pub fn notice(&self) -> Option<&str> {
        self.notice.as_deref()
    }
}

/// One unverified source declaration in a finite local snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconnaissanceSource {
    source_id: String,
    namespace: String,
    revision: String,
    provider_time: Option<String>,
    observed_time: String,
    collection_method: String,
    completeness: ReconnaissanceCompleteness,
    origin: String,
    rights: ReconnaissanceDeclaredRights,
}

impl ReconnaissanceSource {
    /// Returns the snapshot-local declared source identifier.
    #[must_use]
    pub fn source_id(&self) -> &str {
        &self.source_id
    }

    /// Returns the declared provider namespace.
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// Returns the declared provider revision.
    #[must_use]
    pub fn revision(&self) -> &str {
        &self.revision
    }

    /// Returns the inert provider-time declaration, if one was supplied.
    #[must_use]
    pub fn provider_time(&self) -> Option<&str> {
        self.provider_time.as_deref()
    }

    /// Returns the inert observation-time declaration.
    #[must_use]
    pub fn observed_time(&self) -> &str {
        &self.observed_time
    }

    /// Returns the declared collection method token.
    #[must_use]
    pub fn collection_method(&self) -> &str {
        &self.collection_method
    }

    /// Returns the unverified declared completeness.
    #[must_use]
    pub const fn completeness(&self) -> ReconnaissanceCompleteness {
        self.completeness
    }

    /// Returns the inert declared source origin; it grants no network authority.
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// Returns the unverified declared rights metadata.
    #[must_use]
    pub const fn rights(&self) -> &ReconnaissanceDeclaredRights {
        &self.rights
    }
}

/// Transport named by an inert service-banner product hypothesis.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconnaissanceTransport {
    /// Transmission Control Protocol.
    Tcp,
    /// User Datagram Protocol.
    Udp,
}

impl ReconnaissanceTransport {
    /// Returns the V1 wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

/// Closed kind of source-qualified V1 hypothesis record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconnaissanceRecordKind {
    /// A name listed by certificate-transparency-derived material.
    CtName,
    /// A historical DNS name/address association.
    DnsHistory,
    /// A product hint derived from a service banner.
    ServiceBannerProduct,
    /// A label assigned by a reputation source.
    ReputationLabel,
}

impl ReconnaissanceRecordKind {
    /// Returns the V1 wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CtName => "ct_name",
            Self::DnsHistory => "dns_history",
            Self::ServiceBannerProduct => "service_banner_product",
            Self::ReputationLabel => "reputation_label",
        }
    }
}

/// A certificate-transparency-name hypothesis value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CtNameHypothesis {
    name: String,
}

impl CtNameHypothesis {
    /// Returns the bounded ASCII DNS name, optionally beginning with `*.`.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// A historical DNS association hypothesis value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsHistoryHypothesis {
    name: String,
    address: IpAddr,
}

impl DnsHistoryHypothesis {
    /// Returns the bounded ASCII DNS name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the syntactically parsed IP address.
    #[must_use]
    pub const fn address(&self) -> IpAddr {
        self.address
    }
}

/// An inert service-banner product hypothesis value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceBannerProductHypothesis {
    host: String,
    port: u16,
    transport: ReconnaissanceTransport,
    product: String,
    version: Option<String>,
}

impl ServiceBannerProductHypothesis {
    /// Returns the validated ASCII DNS name or IP address text.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Returns the nonzero declared service port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// Returns the closed declared transport.
    #[must_use]
    pub const fn transport(&self) -> ReconnaissanceTransport {
        self.transport
    }

    /// Returns the inert product hint.
    #[must_use]
    pub fn product(&self) -> &str {
        &self.product
    }

    /// Returns the inert optional version hint.
    #[must_use]
    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }
}

/// An inert reputation-label hypothesis value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReputationLabelHypothesis {
    subject: String,
    label: String,
}

impl ReputationLabelHypothesis {
    /// Returns the validated ASCII DNS name or IP address text.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Returns the source-supplied label without interpreting its meaning.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }
}

/// Closed value carried by a source-qualified V1 hypothesis record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReconnaissanceRecordValue {
    /// Certificate-transparency-derived name.
    CtName(CtNameHypothesis),
    /// Historical DNS name/address association.
    DnsHistory(DnsHistoryHypothesis),
    /// Service-banner-derived product hint.
    ServiceBannerProduct(ServiceBannerProductHypothesis),
    /// Source-supplied reputation label.
    ReputationLabel(ReputationLabelHypothesis),
}

impl ReconnaissanceRecordValue {
    /// Returns the closed record kind.
    #[must_use]
    pub const fn kind(&self) -> ReconnaissanceRecordKind {
        match self {
            Self::CtName(_) => ReconnaissanceRecordKind::CtName,
            Self::DnsHistory(_) => ReconnaissanceRecordKind::DnsHistory,
            Self::ServiceBannerProduct(_) => ReconnaissanceRecordKind::ServiceBannerProduct,
            Self::ReputationLabel(_) => ReconnaissanceRecordKind::ReputationLabel,
        }
    }
}

/// One bounded, source-qualified hypothesis record.
///
/// Source references are mandatory and resolved during parsing. This type has
/// no finding, verification, exploitability, target, or request authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconnaissanceRecord {
    record_id: String,
    source_ids: Vec<String>,
    source_indices: Vec<usize>,
    value: ReconnaissanceRecordValue,
}

/// Explicit alias emphasizing the interpretation of every returned record.
pub type ReconnaissanceHypothesis = ReconnaissanceRecord;

impl ReconnaissanceRecord {
    /// Returns the snapshot-local record identifier.
    #[must_use]
    pub fn record_id(&self) -> &str {
        &self.record_id
    }

    /// Returns the nonempty, unique, resolved declared source identifiers.
    #[must_use]
    pub fn source_ids(&self) -> &[String] {
        &self.source_ids
    }

    /// Returns the closed record kind.
    #[must_use]
    pub const fn kind(&self) -> ReconnaissanceRecordKind {
        self.value.kind()
    }

    /// Returns the typed hypothesis value.
    #[must_use]
    pub const fn value(&self) -> &ReconnaissanceRecordValue {
        &self.value
    }

    /// Returns the fixed hypothesis-only interpretation boundary.
    #[must_use]
    pub const fn claim_limit(&self) -> ReconnaissanceClaimLimit {
        ReconnaissanceClaimLimit::SourceQualifiedHypothesesOnly
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PreparedIndex {
    sources: BTreeMap<String, usize>,
    records: BTreeMap<String, usize>,
}

/// One validated finite snapshot plus deterministic lookup indexes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconnaissanceSnapshot {
    snapshot_id: String,
    snapshot_revision: String,
    sources: Vec<ReconnaissanceSource>,
    records: Vec<ReconnaissanceRecord>,
    prepared_index: PreparedIndex,
    audit: ReconnaissanceSnapshotAudit,
}

/// Concise integration alias for a validated offline snapshot.
pub type ReconSnapshot = ReconnaissanceSnapshot;

/// Concise integration alias for strict snapshot import failures.
pub type ReconSnapshotError = ReconnaissanceSnapshotError;

impl ReconnaissanceSnapshot {
    /// Parses one complete strict V1 JSON document from exact local bytes.
    pub fn parse_json(bytes: &[u8]) -> Result<Self, ReconnaissanceSnapshotError> {
        parse_with_limits(
            bytes,
            MAX_RECONNAISSANCE_SNAPSHOT_INPUT_BYTES,
            MAX_RECONNAISSANCE_SNAPSHOT_PREPARED_INDEX_BYTES,
        )
    }

    /// Returns the accepted schema identifier.
    #[must_use]
    pub const fn schema(&self) -> &'static str {
        RECONNAISSANCE_SNAPSHOT_SCHEMA
    }

    /// Returns the stable parser and interpretation policy.
    #[must_use]
    pub const fn policy(&self) -> &'static str {
        RECONNAISSANCE_SNAPSHOT_POLICY
    }

    /// Returns the operator-declared snapshot identifier.
    #[must_use]
    pub fn snapshot_id(&self) -> &str {
        &self.snapshot_id
    }

    /// Returns the operator-declared snapshot revision.
    #[must_use]
    pub fn snapshot_revision(&self) -> &str {
        &self.snapshot_revision
    }

    /// Returns the value-free strict-import audit.
    #[must_use]
    pub const fn audit(&self) -> &ReconnaissanceSnapshotAudit {
        &self.audit
    }

    /// Returns the exact-input identity.
    #[must_use]
    pub const fn input(&self) -> &ReconnaissanceSnapshotInputIdentity {
        &self.audit.input
    }

    /// Returns unverified source declarations in input order.
    #[must_use]
    pub fn sources(&self) -> &[ReconnaissanceSource] {
        &self.sources
    }

    /// Returns source-qualified hypothesis records in input order.
    #[must_use]
    pub fn records(&self) -> &[ReconnaissanceRecord] {
        &self.records
    }

    /// Returns the same records through their explicit hypothesis alias.
    #[must_use]
    pub fn hypotheses(&self) -> &[ReconnaissanceHypothesis] {
        &self.records
    }

    /// Looks up one declared source by its exact snapshot-local identifier.
    #[must_use]
    pub fn source(&self, source_id: &str) -> Option<&ReconnaissanceSource> {
        self.prepared_index
            .sources
            .get(source_id)
            .map(|&index| &self.sources[index])
    }

    /// Looks up one hypothesis record by its exact snapshot-local identifier.
    #[must_use]
    pub fn record(&self, record_id: &str) -> Option<&ReconnaissanceRecord> {
        self.prepared_index
            .records
            .get(record_id)
            .map(|&index| &self.records[index])
    }

    /// Returns the number of declared sources.
    #[must_use]
    pub const fn source_count(&self) -> usize {
        self.audit.source_count
    }

    /// Returns the number of hypothesis records.
    #[must_use]
    pub const fn record_count(&self) -> usize {
        self.audit.record_count
    }

    /// Returns the total number of resolved record-to-source associations.
    #[must_use]
    pub const fn source_association_count(&self) -> usize {
        self.audit.source_association_count
    }

    /// Returns conservative bytes charged to the prepared lookup indexes.
    #[must_use]
    pub const fn prepared_index_bytes(&self) -> usize {
        self.audit.prepared_index_bytes
    }

    /// Returns the fixed no-network/no-archive activity facts.
    #[must_use]
    pub const fn external_activity(&self) -> ReconnaissanceExternalActivity {
        ReconnaissanceExternalActivity
    }

    /// Returns the fixed hypothesis-only interpretation boundary.
    #[must_use]
    pub const fn claim_limit(&self) -> ReconnaissanceClaimLimit {
        ReconnaissanceClaimLimit::SourceQualifiedHypothesesOnly
    }
}

/// Parses one complete strict V1 JSON document from exact local bytes.
pub fn parse_reconnaissance_snapshot(
    bytes: &[u8],
) -> Result<ReconnaissanceSnapshot, ReconnaissanceSnapshotError> {
    ReconnaissanceSnapshot::parse_json(bytes)
}

/// Parses one complete strict V1 JSON document using the concise integration
/// names retained by assessment and reporting surfaces.
pub fn parse_recon_snapshot(bytes: &[u8]) -> Result<ReconSnapshot, ReconSnapshotError> {
    parse_reconnaissance_snapshot(bytes)
}

/// Static, value-free failure from strict reconnaissance snapshot import.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum ReconnaissanceSnapshotError {
    /// No exact input bytes were supplied.
    #[error("reconnaissance snapshot input is empty")]
    EmptyInput,
    /// The exact input exceeded the one-MiB ceiling.
    #[error("reconnaissance snapshot input exceeds its byte limit")]
    InputTooLarge,
    /// The input was not one complete JSON value.
    #[error("reconnaissance snapshot input is malformed JSON")]
    MalformedJson,
    /// A JSON object contained a duplicate decoded key.
    #[error("reconnaissance snapshot input contains a duplicate JSON key")]
    DuplicateJsonKey,
    /// JSON depth, nodes, members, arrays, keys, or strings exceeded a bound.
    #[error("reconnaissance snapshot input exceeds a structural limit")]
    StructuralLimitExceeded,
    /// The document did not select the exact V1 schema.
    #[error("reconnaissance snapshot schema is unsupported")]
    UnsupportedSchema,
    /// A required field, strict type, closed value, or bounded scalar was invalid.
    #[error("reconnaissance snapshot contains an invalid or unsupported value")]
    InvalidSnapshot,
    /// More source declarations were supplied than V1 permits.
    #[error("reconnaissance snapshot contains too many sources")]
    TooManySources,
    /// Two source declarations used the same source identifier.
    #[error("reconnaissance snapshot contains a duplicate source identifier")]
    DuplicateSourceId,
    /// More hypothesis records were supplied than V1 permits.
    #[error("reconnaissance snapshot contains too many records")]
    TooManyRecords,
    /// Two hypothesis records used the same record identifier.
    #[error("reconnaissance snapshot contains a duplicate record identifier")]
    DuplicateRecordId,
    /// One record repeated a source identifier.
    #[error("reconnaissance snapshot record contains a duplicate source reference")]
    DuplicateRecordSource,
    /// One record referred to a source declaration that does not exist.
    #[error("reconnaissance snapshot record contains an unresolved source reference")]
    UnknownRecordSource,
    /// Total record-to-source associations exceeded the V1 ceiling.
    #[error("reconnaissance snapshot contains too many source associations")]
    TooManySourceAssociations,
    /// Prepared deterministic lookup state exceeded its memory ceiling.
    #[error("reconnaissance snapshot prepared index exceeds its byte limit")]
    PreparedIndexTooLarge,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotWire {
    schema: String,
    snapshot_id: String,
    snapshot_revision: String,
    sources: Vec<SourceWire>,
    records: Vec<RecordWire>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceWire {
    source_id: String,
    namespace: String,
    revision: String,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    provider_time: RequiredNullable<String>,
    observed_time: String,
    collection_method: String,
    completeness: CompletenessWire,
    origin: String,
    rights: RightsWire,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RightsWire {
    status: RightsStatusWire,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    attribution: RequiredNullable<String>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    notice: RequiredNullable<String>,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CompletenessWire {
    CompleteAsDeclared,
    PartialAsDeclared,
    Unknown,
}

impl From<CompletenessWire> for ReconnaissanceCompleteness {
    fn from(value: CompletenessWire) -> Self {
        match value {
            CompletenessWire::CompleteAsDeclared => Self::CompleteAsDeclared,
            CompletenessWire::PartialAsDeclared => Self::PartialAsDeclared,
            CompletenessWire::Unknown => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RightsStatusWire {
    PermittedAsDeclared,
    RestrictedAsDeclared,
    Unknown,
}

impl From<RightsStatusWire> for ReconnaissanceDeclaredRightsStatus {
    fn from(value: RightsStatusWire) -> Self {
        match value {
            RightsStatusWire::PermittedAsDeclared => Self::PermittedAsDeclared,
            RightsStatusWire::RestrictedAsDeclared => Self::RestrictedAsDeclared,
            RightsStatusWire::Unknown => Self::Unknown,
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum RecordWire {
    CtName {
        record_id: String,
        source_ids: Vec<String>,
        name: String,
    },
    DnsHistory {
        record_id: String,
        source_ids: Vec<String>,
        name: String,
        address: String,
    },
    ServiceBannerProduct {
        record_id: String,
        source_ids: Vec<String>,
        host: String,
        port: u16,
        transport: TransportWire,
        product: String,
        #[serde(deserialize_with = "deserialize_required_nullable")]
        version: RequiredNullable<String>,
    },
    ReputationLabel {
        record_id: String,
        source_ids: Vec<String>,
        subject: String,
        label: String,
    },
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum TransportWire {
    Tcp,
    Udp,
}

impl From<TransportWire> for ReconnaissanceTransport {
    fn from(value: TransportWire) -> Self {
        match value {
            TransportWire::Tcp => Self::Tcp,
            TransportWire::Udp => Self::Udp,
        }
    }
}

struct RequiredNullable<T>(Option<T>);

fn deserialize_required_nullable<'de, D, T>(
    deserializer: D,
) -> Result<RequiredNullable<T>, D::Error>
where
    T: Deserialize<'de>,
    D: Deserializer<'de>,
{
    Option::<T>::deserialize(deserializer).map(RequiredNullable)
}

struct RecordParts {
    record_id: String,
    source_ids: Vec<String>,
    value: ReconnaissanceRecordValue,
}

impl RecordWire {
    fn validate(self) -> Result<RecordParts, ReconnaissanceSnapshotError> {
        match self {
            Self::CtName {
                record_id,
                source_ids,
                name,
            } => {
                if !valid_dns_name(&name, true) {
                    return Err(ReconnaissanceSnapshotError::InvalidSnapshot);
                }
                Ok(RecordParts {
                    record_id,
                    source_ids,
                    value: ReconnaissanceRecordValue::CtName(CtNameHypothesis {
                        name: tight_string(name),
                    }),
                })
            },
            Self::DnsHistory {
                record_id,
                source_ids,
                name,
                address,
            } => {
                if !valid_dns_name(&name, false) {
                    return Err(ReconnaissanceSnapshotError::InvalidSnapshot);
                }
                let address = address
                    .parse::<IpAddr>()
                    .map_err(|_| ReconnaissanceSnapshotError::InvalidSnapshot)?;
                Ok(RecordParts {
                    record_id,
                    source_ids,
                    value: ReconnaissanceRecordValue::DnsHistory(DnsHistoryHypothesis {
                        name: tight_string(name),
                        address,
                    }),
                })
            },
            Self::ServiceBannerProduct {
                record_id,
                source_ids,
                host,
                port,
                transport,
                product,
                version,
            } => {
                if !valid_host(&host)
                    || port == 0
                    || !valid_bounded_text(&product, MAX_PRODUCT_BYTES)
                    || version
                        .0
                        .as_deref()
                        .is_some_and(|value| !valid_bounded_text(value, MAX_VERSION_BYTES))
                {
                    return Err(ReconnaissanceSnapshotError::InvalidSnapshot);
                }
                Ok(RecordParts {
                    record_id,
                    source_ids,
                    value: ReconnaissanceRecordValue::ServiceBannerProduct(
                        ServiceBannerProductHypothesis {
                            host: tight_string(host),
                            port,
                            transport: transport.into(),
                            product: tight_string(product),
                            version: version.0.map(tight_string),
                        },
                    ),
                })
            },
            Self::ReputationLabel {
                record_id,
                source_ids,
                subject,
                label,
            } => {
                if !valid_host(&subject) || !valid_bounded_text(&label, MAX_LABEL_BYTES) {
                    return Err(ReconnaissanceSnapshotError::InvalidSnapshot);
                }
                Ok(RecordParts {
                    record_id,
                    source_ids,
                    value: ReconnaissanceRecordValue::ReputationLabel(ReputationLabelHypothesis {
                        subject: tight_string(subject),
                        label: tight_string(label),
                    }),
                })
            },
        }
    }
}

fn parse_with_limits(
    bytes: &[u8],
    maximum_input_bytes: usize,
    maximum_prepared_index_bytes: usize,
) -> Result<ReconnaissanceSnapshot, ReconnaissanceSnapshotError> {
    if bytes.is_empty() {
        return Err(ReconnaissanceSnapshotError::EmptyInput);
    }
    if bytes.len() > maximum_input_bytes {
        return Err(ReconnaissanceSnapshotError::InputTooLarge);
    }

    let value = parse_strict_json(bytes)?;
    let wire: SnapshotWire =
        serde_json::from_value(value).map_err(|_| ReconnaissanceSnapshotError::InvalidSnapshot)?;
    if wire.schema != RECONNAISSANCE_SNAPSHOT_SCHEMA {
        return Err(ReconnaissanceSnapshotError::UnsupportedSchema);
    }
    if !valid_identifier(&wire.snapshot_id) || !valid_identifier(&wire.snapshot_revision) {
        return Err(ReconnaissanceSnapshotError::InvalidSnapshot);
    }
    if wire.sources.is_empty() {
        return Err(ReconnaissanceSnapshotError::InvalidSnapshot);
    }
    if wire.sources.len() > MAX_RECONNAISSANCE_SNAPSHOT_SOURCES {
        return Err(ReconnaissanceSnapshotError::TooManySources);
    }
    if wire.records.len() > MAX_RECONNAISSANCE_SNAPSHOT_RECORDS {
        return Err(ReconnaissanceSnapshotError::TooManyRecords);
    }

    let mut index_budget = PreparedIndexBudget::new(maximum_prepared_index_bytes)?;
    let mut source_index = BTreeMap::new();
    let mut sources = Vec::with_capacity(wire.sources.len());
    for source in wire.sources {
        let source = validate_source(source)?;
        if source_index.contains_key(source.source_id()) {
            return Err(ReconnaissanceSnapshotError::DuplicateSourceId);
        }
        index_budget.add_map_entry(source.source_id())?;
        source_index.insert(source.source_id.clone(), sources.len());
        sources.push(source);
    }

    let mut record_index = BTreeMap::new();
    let mut records = Vec::with_capacity(wire.records.len());
    let mut source_association_count = 0_usize;
    for record in wire.records {
        let parts = record.validate()?;
        if !valid_identifier(&parts.record_id) {
            return Err(ReconnaissanceSnapshotError::InvalidSnapshot);
        }
        if record_index.contains_key(&parts.record_id) {
            return Err(ReconnaissanceSnapshotError::DuplicateRecordId);
        }
        if parts.source_ids.is_empty() {
            return Err(ReconnaissanceSnapshotError::InvalidSnapshot);
        }
        source_association_count = source_association_count
            .checked_add(parts.source_ids.len())
            .filter(|count| *count <= MAX_RECONNAISSANCE_SNAPSHOT_SOURCE_ASSOCIATIONS)
            .ok_or(ReconnaissanceSnapshotError::TooManySourceAssociations)?;

        let mut unique_sources = BTreeSet::new();
        let mut source_ids = Vec::with_capacity(parts.source_ids.len());
        let mut source_indices = Vec::with_capacity(parts.source_ids.len());
        for source_id in parts.source_ids {
            if !valid_identifier(&source_id) {
                return Err(ReconnaissanceSnapshotError::InvalidSnapshot);
            }
            if !unique_sources.insert(source_id.clone()) {
                return Err(ReconnaissanceSnapshotError::DuplicateRecordSource);
            }
            let source_index = source_index
                .get(&source_id)
                .copied()
                .ok_or(ReconnaissanceSnapshotError::UnknownRecordSource)?;
            source_ids.push(tight_string(source_id));
            source_indices.push(source_index);
        }
        index_budget.add_map_entry(&parts.record_id)?;
        index_budget.add_resolved_sources(source_indices.capacity())?;
        record_index.insert(parts.record_id.clone(), records.len());
        records.push(ReconnaissanceRecord {
            record_id: tight_string(parts.record_id),
            source_ids,
            source_indices,
            value: parts.value,
        });
    }

    sources.shrink_to_fit();
    records.shrink_to_fit();
    let byte_length =
        u64::try_from(bytes.len()).map_err(|_| ReconnaissanceSnapshotError::InputTooLarge)?;
    let input = ReconnaissanceSnapshotInputIdentity {
        byte_length,
        sha256: Sha256::digest(bytes).into(),
    };
    let audit = ReconnaissanceSnapshotAudit {
        input,
        source_count: sources.len(),
        record_count: records.len(),
        source_association_count,
        prepared_index_bytes: index_budget.used(),
    };
    Ok(ReconnaissanceSnapshot {
        snapshot_id: tight_string(wire.snapshot_id),
        snapshot_revision: tight_string(wire.snapshot_revision),
        sources,
        records,
        prepared_index: PreparedIndex {
            sources: source_index,
            records: record_index,
        },
        audit,
    })
}

fn validate_source(wire: SourceWire) -> Result<ReconnaissanceSource, ReconnaissanceSnapshotError> {
    if !valid_identifier(&wire.source_id)
        || !valid_identifier(&wire.namespace)
        || !valid_identifier(&wire.revision)
        || wire
            .provider_time
            .0
            .as_deref()
            .is_some_and(|value| !valid_ascii_text(value, MAX_TIMESTAMP_BYTES))
        || !valid_ascii_text(&wire.observed_time, MAX_TIMESTAMP_BYTES)
        || !valid_identifier(&wire.collection_method)
        || !valid_bounded_text(&wire.origin, MAX_ORIGIN_BYTES)
        || wire
            .rights
            .attribution
            .0
            .as_deref()
            .is_some_and(|value| !valid_bounded_text(value, MAX_RIGHTS_TEXT_BYTES))
        || wire
            .rights
            .notice
            .0
            .as_deref()
            .is_some_and(|value| !valid_bounded_text(value, MAX_RIGHTS_TEXT_BYTES))
    {
        return Err(ReconnaissanceSnapshotError::InvalidSnapshot);
    }

    Ok(ReconnaissanceSource {
        source_id: tight_string(wire.source_id),
        namespace: tight_string(wire.namespace),
        revision: tight_string(wire.revision),
        provider_time: wire.provider_time.0.map(tight_string),
        observed_time: tight_string(wire.observed_time),
        collection_method: tight_string(wire.collection_method),
        completeness: wire.completeness.into(),
        origin: tight_string(wire.origin),
        rights: ReconnaissanceDeclaredRights {
            status: wire.rights.status.into(),
            attribution: wire.rights.attribution.0.map(tight_string),
            notice: wire.rights.notice.0.map(tight_string),
        },
    })
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'@' | b'-')
        })
}

fn valid_ascii_text(value: &str, maximum: usize) -> bool {
    valid_bounded_text(value, maximum) && value.is_ascii()
}

fn valid_bounded_text(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && !value.starts_with(char::is_whitespace)
        && !value.ends_with(char::is_whitespace)
        && !value.chars().any(char::is_control)
}

fn valid_host(value: &str) -> bool {
    value.parse::<IpAddr>().is_ok() || valid_dns_name(value, false)
}

fn valid_dns_name(value: &str, allow_wildcard: bool) -> bool {
    if value.is_empty() || value.len() > MAX_DNS_NAME_BYTES || !value.is_ascii() {
        return false;
    }
    let value = if allow_wildcard {
        value.strip_prefix("*.").unwrap_or(value)
    } else {
        value
    };
    if value.is_empty() || value.starts_with('.') || value.ends_with('.') {
        return false;
    }
    value.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label.as_bytes()[0].is_ascii_alphanumeric()
            && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

fn tight_string(mut value: String) -> String {
    value.shrink_to_fit();
    value
}

fn hex_digest(bytes: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

struct PreparedIndexBudget {
    used: usize,
    maximum: usize,
}

impl PreparedIndexBudget {
    fn new(maximum: usize) -> Result<Self, ReconnaissanceSnapshotError> {
        let used = size_of::<PreparedIndex>();
        if used > maximum {
            return Err(ReconnaissanceSnapshotError::PreparedIndexTooLarge);
        }
        Ok(Self { used, maximum })
    }

    fn add_map_entry(&mut self, key: &str) -> Result<(), ReconnaissanceSnapshotError> {
        self.add(size_of::<String>())?;
        self.add(size_of::<usize>())?;
        self.add(key.len())?;
        self.add(CONSERVATIVE_BTREE_ENTRY_OVERHEAD)
    }

    fn add_resolved_sources(&mut self, capacity: usize) -> Result<(), ReconnaissanceSnapshotError> {
        let bytes = capacity
            .checked_mul(size_of::<usize>())
            .ok_or(ReconnaissanceSnapshotError::PreparedIndexTooLarge)?;
        self.add(bytes)
    }

    fn add(&mut self, bytes: usize) -> Result<(), ReconnaissanceSnapshotError> {
        self.used = self
            .used
            .checked_add(bytes)
            .filter(|used| *used <= self.maximum)
            .ok_or(ReconnaissanceSnapshotError::PreparedIndexTooLarge)?;
        Ok(())
    }

    const fn used(&self) -> usize {
        self.used
    }
}

#[derive(Default)]
struct JsonBudget {
    nodes: usize,
    members: usize,
    array_items: usize,
}

impl JsonBudget {
    fn enter<E: de::Error>(&mut self, depth: usize) -> Result<(), E> {
        if depth > MAX_JSON_DEPTH || self.nodes >= MAX_JSON_NODES {
            return Err(E::custom(JSON_LIMIT_MARKER));
        }
        self.nodes += 1;
        Ok(())
    }

    fn member<E: de::Error>(&mut self) -> Result<(), E> {
        if self.members >= MAX_JSON_MEMBERS {
            return Err(E::custom(JSON_LIMIT_MARKER));
        }
        self.members += 1;
        Ok(())
    }

    fn array_item<E: de::Error>(&mut self) -> Result<(), E> {
        if self.array_items >= MAX_JSON_ARRAY_ITEMS {
            return Err(E::custom(JSON_LIMIT_MARKER));
        }
        self.array_items += 1;
        Ok(())
    }
}

struct StrictJsonSeed<'a> {
    budget: &'a mut JsonBudget,
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for StrictJsonSeed<'_> {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        self.budget.enter::<D::Error>(self.depth)?;
        deserializer.deserialize_any(StrictJsonVisitor {
            budget: self.budget,
            depth: self.depth,
        })
    }
}

struct StrictJsonVisitor<'a> {
    budget: &'a mut JsonBudget,
    depth: usize,
}

impl<'de> Visitor<'de> for StrictJsonVisitor<'_> {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded reconnaissance snapshot JSON")
    }

    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Self::Value, E> {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_borrowed_str<E: de::Error>(self, value: &'de str) -> Result<Self::Value, E> {
        self.visit_str(value)
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        if value.len() > MAX_JSON_STRING_BYTES {
            return Err(E::custom(JSON_LIMIT_MARKER));
        }
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
        if value.len() > MAX_JSON_STRING_BYTES {
            return Err(E::custom(JSON_LIMIT_MARKER));
        }
        Ok(Value::String(value))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(StrictJsonSeed {
            budget: &mut *self.budget,
            depth: self.depth + 1,
        })? {
            self.budget.array_item::<A::Error>()?;
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = serde_json::Map::new();
        while let Some(key) = map.next_key_seed(StrictKeySeed)? {
            if values.contains_key(&key) {
                return Err(de::Error::custom(DUPLICATE_KEY_MARKER));
            }
            self.budget.member::<A::Error>()?;
            let value = map.next_value_seed(StrictJsonSeed {
                budget: &mut *self.budget,
                depth: self.depth + 1,
            })?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

struct StrictKeySeed;

impl<'de> DeserializeSeed<'de> for StrictKeySeed {
    type Value = String;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(StrictKeyVisitor)
    }
}

struct StrictKeyVisitor;

impl Visitor<'_> for StrictKeyVisitor {
    type Value = String;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded reconnaissance snapshot object key")
    }

    fn visit_borrowed_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        self.visit_str(value)
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        if value.len() > MAX_JSON_KEY_BYTES {
            return Err(E::custom(JSON_LIMIT_MARKER));
        }
        Ok(value.to_owned())
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
        if value.len() > MAX_JSON_KEY_BYTES {
            return Err(E::custom(JSON_LIMIT_MARKER));
        }
        Ok(value)
    }
}

fn parse_strict_json(bytes: &[u8]) -> Result<Value, ReconnaissanceSnapshotError> {
    let mut budget = JsonBudget::default();
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = StrictJsonSeed {
        budget: &mut budget,
        depth: 0,
    }
    .deserialize(&mut deserializer)
    .map_err(classify_json_error)?;
    deserializer.end().map_err(classify_json_error)?;
    Ok(value)
}

fn classify_json_error(error: serde_json::Error) -> ReconnaissanceSnapshotError {
    let message = error.to_string();
    if message.contains(DUPLICATE_KEY_MARKER) {
        ReconnaissanceSnapshotError::DuplicateJsonKey
    } else if message.contains(JSON_LIMIT_MARKER) {
        ReconnaissanceSnapshotError::StructuralLimitExceeded
    } else {
        ReconnaissanceSnapshotError::MalformedJson
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};

    use super::*;

    fn source(id: &str) -> Value {
        json!({
            "source_id": id,
            "namespace": "provider.example",
            "revision": "feed-2026-09",
            "provider_time": null,
            "observed_time": "2026-09-20T10:30:00Z",
            "collection_method": "offline-export",
            "completeness": "partial_as_declared",
            "origin": "https://provider.example/export",
            "rights": {
                "status": "permitted_as_declared",
                "attribution": "Synthetic fixture provider",
                "notice": null
            }
        })
    }

    fn document() -> Value {
        json!({
            "schema": RECONNAISSANCE_SNAPSHOT_SCHEMA,
            "snapshot_id": "snapshot-fixture",
            "snapshot_revision": "revision-1",
            "sources": [source("source-a"), source("source-b")],
            "records": [
                {
                    "kind": "ct_name",
                    "record_id": "record-ct",
                    "source_ids": ["source-a"],
                    "name": "*.example.test"
                },
                {
                    "kind": "dns_history",
                    "record_id": "record-dns",
                    "source_ids": ["source-a", "source-b"],
                    "name": "api.example.test",
                    "address": "192.0.2.10"
                },
                {
                    "kind": "service_banner_product",
                    "record_id": "record-service",
                    "source_ids": ["source-b"],
                    "host": "192.0.2.10",
                    "port": 443,
                    "transport": "tcp",
                    "product": "fixture-server",
                    "version": null
                },
                {
                    "kind": "reputation_label",
                    "record_id": "record-reputation",
                    "source_ids": ["source-a"],
                    "subject": "api.example.test",
                    "label": "source-listed"
                }
            ]
        })
    }

    fn encode(value: &Value) -> Vec<u8> {
        serde_json::to_vec(value).unwrap()
    }

    #[test]
    fn parses_all_closed_hypotheses_and_exposes_audit_without_authority() {
        let bytes = encode(&document());
        let snapshot = parse_reconnaissance_snapshot(&bytes).unwrap();

        assert_eq!(snapshot.schema(), RECONNAISSANCE_SNAPSHOT_SCHEMA);
        assert_eq!(snapshot.policy(), RECONNAISSANCE_SNAPSHOT_POLICY);
        assert_eq!(snapshot.snapshot_id(), "snapshot-fixture");
        assert_eq!(snapshot.snapshot_revision(), "revision-1");
        assert_eq!(snapshot.input().byte_length(), bytes.len() as u64);
        assert_eq!(
            snapshot.input().sha256(),
            &<[u8; 32]>::from(Sha256::digest(&bytes))
        );
        assert_eq!(snapshot.source_count(), 2);
        assert_eq!(snapshot.record_count(), 4);
        assert_eq!(snapshot.source_association_count(), 5);
        assert!(
            snapshot.prepared_index_bytes() <= MAX_RECONNAISSANCE_SNAPSHOT_PREPARED_INDEX_BYTES
        );
        assert_eq!(
            snapshot.claim_limit().as_str(),
            "source_qualified_hypotheses_only"
        );
        let activity = snapshot.external_activity();
        assert_eq!(activity.target_request_count(), 0);
        assert_eq!(activity.provider_request_count(), 0);
        assert_eq!(activity.archive_processing().as_str(), "not_performed");
        assert_eq!(activity.decompression().as_str(), "not_performed");

        let source = snapshot.source("source-a").unwrap();
        assert_eq!(source.namespace(), "provider.example");
        assert_eq!(source.provider_time(), None);
        assert_eq!(
            source.completeness(),
            ReconnaissanceCompleteness::PartialAsDeclared
        );
        assert_eq!(
            source.rights().status(),
            ReconnaissanceDeclaredRightsStatus::PermittedAsDeclared
        );
        assert_eq!(
            source.rights().attribution(),
            Some("Synthetic fixture provider")
        );

        assert!(matches!(
            snapshot.record("record-ct").unwrap().value(),
            ReconnaissanceRecordValue::CtName(value) if value.name() == "*.example.test"
        ));
        assert!(matches!(
            snapshot.record("record-dns").unwrap().value(),
            ReconnaissanceRecordValue::DnsHistory(value)
                if value.address() == "192.0.2.10".parse::<IpAddr>().unwrap()
        ));
        assert!(matches!(
            snapshot.record("record-service").unwrap().value(),
            ReconnaissanceRecordValue::ServiceBannerProduct(value)
                if value.port() == 443
                    && value.transport() == ReconnaissanceTransport::Tcp
                    && value.version().is_none()
        ));
        assert!(matches!(
            snapshot.record("record-reputation").unwrap().value(),
            ReconnaissanceRecordValue::ReputationLabel(value)
                if value.label() == "source-listed"
        ));
    }

    #[test]
    fn exact_input_identity_is_separate_from_declared_snapshot_provenance() {
        let compact = encode(&document());
        let pretty = serde_json::to_vec_pretty(&document()).unwrap();
        let compact = parse_reconnaissance_snapshot(&compact).unwrap();
        let pretty = parse_reconnaissance_snapshot(&pretty).unwrap();

        assert_eq!(compact.snapshot_id(), pretty.snapshot_id());
        assert_eq!(compact.snapshot_revision(), pretty.snapshot_revision());
        assert_ne!(compact.input().byte_length(), pretty.input().byte_length());
        assert_ne!(compact.input().sha256(), pretty.input().sha256());
    }

    #[test]
    fn duplicate_json_keys_are_rejected_at_every_depth_after_decoding() {
        let record =
            r#"{"kind":"ct_name","record_id":"r","source_ids":["s"],"name":"example.test"}"#;
        let source = r#"{"source_id":"s","namespace":"n","revision":"r","provider_time":null,"observed_time":"t","collection_method":"m","completeness":"unknown","origin":"o","rights":{"status":"unknown","attribution":null,"notice":null}}"#;
        let root = format!(
            r#"{{"schema":"{RECONNAISSANCE_SNAPSHOT_SCHEMA}","schema":"{RECONNAISSANCE_SNAPSHOT_SCHEMA}","snapshot_id":"s","snapshot_revision":"r","sources":[{source}],"records":[{record}]}}"#
        );
        assert_eq!(
            parse_reconnaissance_snapshot(root.as_bytes()),
            Err(ReconnaissanceSnapshotError::DuplicateJsonKey)
        );

        let nested = format!(
            r#"{{"schema":"{RECONNAISSANCE_SNAPSHOT_SCHEMA}","snapshot_id":"s","snapshot_revision":"r","sources":[{{"source_id":"s","namespace":"n","revision":"r","provider_time":null,"observed_time":"t","collection_method":"m","completeness":"unknown","origin":"o","rights":{{"status":"unknown","attribution":null,"not\u0069ce":null,"notice":"duplicate"}}}}],"records":[{record}]}}"#
        );
        assert_eq!(
            parse_reconnaissance_snapshot(nested.as_bytes()),
            Err(ReconnaissanceSnapshotError::DuplicateJsonKey)
        );
    }

    #[test]
    fn duplicate_and_unresolved_identities_fail_closed() {
        let mut duplicate_source = document();
        duplicate_source["sources"][1]["source_id"] = json!("source-a");
        assert_eq!(
            parse_reconnaissance_snapshot(&encode(&duplicate_source)),
            Err(ReconnaissanceSnapshotError::DuplicateSourceId)
        );

        let mut duplicate_record = document();
        duplicate_record["records"][1]["record_id"] = json!("record-ct");
        assert_eq!(
            parse_reconnaissance_snapshot(&encode(&duplicate_record)),
            Err(ReconnaissanceSnapshotError::DuplicateRecordId)
        );

        let mut duplicate_link = document();
        duplicate_link["records"][0]["source_ids"] = json!(["source-a", "source-a"]);
        assert_eq!(
            parse_reconnaissance_snapshot(&encode(&duplicate_link)),
            Err(ReconnaissanceSnapshotError::DuplicateRecordSource)
        );

        let mut unknown = document();
        unknown["records"][0]["source_ids"] = json!(["source-missing"]);
        assert_eq!(
            parse_reconnaissance_snapshot(&encode(&unknown)),
            Err(ReconnaissanceSnapshotError::UnknownRecordSource)
        );
    }

    #[test]
    fn nullable_fields_are_required_and_types_are_strict() {
        for pointer in [
            "/sources/0/provider_time",
            "/sources/0/rights/attribution",
            "/sources/0/rights/notice",
            "/records/2/version",
        ] {
            let mut value = document();
            let (parent, field) = pointer.rsplit_once('/').unwrap();
            value
                .pointer_mut(parent)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove(field);
            assert_eq!(
                parse_reconnaissance_snapshot(&encode(&value)),
                Err(ReconnaissanceSnapshotError::InvalidSnapshot),
                "{pointer}"
            );
        }

        let mut boolean_port = document();
        boolean_port["records"][2]["port"] = json!(true);
        assert_eq!(
            parse_reconnaissance_snapshot(&encode(&boolean_port)),
            Err(ReconnaissanceSnapshotError::InvalidSnapshot)
        );

        let mut integer_completeness = document();
        integer_completeness["sources"][0]["completeness"] = json!(1);
        assert_eq!(
            parse_reconnaissance_snapshot(&encode(&integer_completeness)),
            Err(ReconnaissanceSnapshotError::InvalidSnapshot)
        );
    }

    #[test]
    fn unknown_fields_and_open_ended_enum_values_are_rejected() {
        let mut unknown_root = document();
        unknown_root["target"] = json!("https://example.test");
        assert_eq!(
            parse_reconnaissance_snapshot(&encode(&unknown_root)),
            Err(ReconnaissanceSnapshotError::InvalidSnapshot)
        );

        let mut unknown_record = document();
        unknown_record["records"][0]["confidence"] = json!(true);
        assert_eq!(
            parse_reconnaissance_snapshot(&encode(&unknown_record)),
            Err(ReconnaissanceSnapshotError::InvalidSnapshot)
        );

        let mut kind = document();
        kind["records"][0]["kind"] = json!("active_probe");
        assert_eq!(
            parse_reconnaissance_snapshot(&encode(&kind)),
            Err(ReconnaissanceSnapshotError::InvalidSnapshot)
        );

        let mut rights = document();
        rights["sources"][0]["rights"]["status"] = json!("verified_permitted");
        assert_eq!(
            parse_reconnaissance_snapshot(&encode(&rights)),
            Err(ReconnaissanceSnapshotError::InvalidSnapshot)
        );
    }

    #[test]
    fn host_name_address_and_text_boundaries_are_enforced() {
        for invalid_name in [
            "https://example.test",
            "user@example.test",
            "bad name.example",
            "-bad.example",
            "bad-.example",
            "*.example.test/path",
            "éxample.test",
        ] {
            let mut value = document();
            value["records"][0]["name"] = json!(invalid_name);
            assert_eq!(
                parse_reconnaissance_snapshot(&encode(&value)),
                Err(ReconnaissanceSnapshotError::InvalidSnapshot),
                "{invalid_name}"
            );
        }

        let mut wildcard_dns = document();
        wildcard_dns["records"][1]["name"] = json!("*.example.test");
        assert_eq!(
            parse_reconnaissance_snapshot(&encode(&wildcard_dns)),
            Err(ReconnaissanceSnapshotError::InvalidSnapshot)
        );

        let mut invalid_address = document();
        invalid_address["records"][1]["address"] = json!("999.0.2.1");
        assert_eq!(
            parse_reconnaissance_snapshot(&encode(&invalid_address)),
            Err(ReconnaissanceSnapshotError::InvalidSnapshot)
        );

        let mut zero_port = document();
        zero_port["records"][2]["port"] = json!(0);
        assert_eq!(
            parse_reconnaissance_snapshot(&encode(&zero_port)),
            Err(ReconnaissanceSnapshotError::InvalidSnapshot)
        );

        let mut control = document();
        control["records"][3]["label"] = json!("bad\nlabel");
        assert_eq!(
            parse_reconnaissance_snapshot(&encode(&control)),
            Err(ReconnaissanceSnapshotError::InvalidSnapshot)
        );
    }

    #[test]
    fn byte_structure_record_association_and_index_limits_fail_closed() {
        assert_eq!(
            parse_reconnaissance_snapshot(&[]),
            Err(ReconnaissanceSnapshotError::EmptyInput)
        );
        assert_eq!(
            parse_reconnaissance_snapshot(&vec![b' '; MAX_RECONNAISSANCE_SNAPSHOT_INPUT_BYTES + 1]),
            Err(ReconnaissanceSnapshotError::InputTooLarge)
        );

        let mut no_sources = document();
        no_sources["sources"] = json!([]);
        no_sources["records"] = json!([]);
        assert_eq!(
            parse_reconnaissance_snapshot(&encode(&no_sources)),
            Err(ReconnaissanceSnapshotError::InvalidSnapshot)
        );

        let mut too_many_sources = document();
        too_many_sources["sources"] = Value::Array(
            (0..=MAX_RECONNAISSANCE_SNAPSHOT_SOURCES)
                .map(|index| source(&format!("source-{index}")))
                .collect(),
        );
        assert_eq!(
            parse_reconnaissance_snapshot(&encode(&too_many_sources)),
            Err(ReconnaissanceSnapshotError::TooManySources)
        );

        let nested = format!(
            "{}0{}",
            "[".repeat(MAX_JSON_DEPTH + 1),
            "]".repeat(MAX_JSON_DEPTH + 1)
        );
        assert_eq!(
            parse_reconnaissance_snapshot(nested.as_bytes()),
            Err(ReconnaissanceSnapshotError::StructuralLimitExceeded)
        );

        let mut too_many_records = document();
        let template = too_many_records["records"][0].clone();
        too_many_records["records"] = Value::Array(
            (0..=MAX_RECONNAISSANCE_SNAPSHOT_RECORDS)
                .map(|index| {
                    let mut record = template.clone();
                    record["record_id"] = json!(format!("record-{index}"));
                    record
                })
                .collect(),
        );
        assert_eq!(
            parse_reconnaissance_snapshot(&encode(&too_many_records)),
            Err(ReconnaissanceSnapshotError::TooManyRecords)
        );

        let mut too_many_associations = document();
        too_many_associations["records"] = Value::Array(
            (0..MAX_RECONNAISSANCE_SNAPSHOT_RECORDS)
                .map(|index| {
                    json!({
                        "kind": "ct_name",
                        "record_id": format!("record-{index}"),
                        "source_ids": ["source-a", "source-b", "source-a2", "source-b2", "source-c"],
                        "name": "example.test"
                    })
                })
                .collect(),
        );
        too_many_associations["sources"] = json!([
            source("source-a"),
            source("source-b"),
            source("source-a2"),
            source("source-b2"),
            source("source-c")
        ]);
        assert_eq!(
            parse_reconnaissance_snapshot(&encode(&too_many_associations)),
            Err(ReconnaissanceSnapshotError::TooManySourceAssociations)
        );

        let bytes = encode(&document());
        assert_eq!(
            parse_with_limits(&bytes, MAX_RECONNAISSANCE_SNAPSHOT_INPUT_BYTES, 1),
            Err(ReconnaissanceSnapshotError::PreparedIndexTooLarge)
        );
    }

    #[test]
    fn compressed_or_archive_inputs_are_never_interpreted() {
        for bytes in [
            b"PK\x03\x04not-a-json-snapshot".as_slice(),
            b"\x1f\x8b\x08not-a-json-snapshot".as_slice(),
        ] {
            assert_eq!(
                parse_reconnaissance_snapshot(bytes),
                Err(ReconnaissanceSnapshotError::MalformedJson)
            );
        }
    }
}
