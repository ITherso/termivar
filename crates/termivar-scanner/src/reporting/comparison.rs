//! Offline, display-only comparison of untrusted rendered assessment documents.
//!
//! Importing a document does not authenticate its origin, establish equal scan
//! coverage, or mint runtime evidence, findings, verification, or target authority.
//! Report-local reference numbers are validated but never used as stable identity.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
};

use serde::Serialize;
use serde_json::Value;

use super::{render_serializable_json, write_markdown_code_span, RenderBuffer, ReportError};

mod html;
mod import;
#[cfg(test)]
#[path = "comparison_tests.rs"]
mod tests;

/// Versioned display-only comparison document schema.
pub const COMPARISON_DOCUMENT_SCHEMA: &str = "termivar-report-comparison/v1";
/// Additive display-only comparison for supplied-session context and coverage.
pub(super) const SUPPLIED_SESSION_COMPARISON_SCHEMA: &str =
    "termivar-supplied-session-comparison/v1";
/// Additive, display-only passive secret-exposure comparison section.
pub(super) const SECRET_EXPOSURE_COMPARISON_SCHEMA: &str = "termivar-secret-exposure-comparison/v1";
/// Additive, display-only passive TLS observation comparison section.
pub(super) const TLS_OBSERVATION_COMPARISON_SCHEMA: &str = "termivar-tls-observation-comparison/v1";
/// Additive, display-only local JWT policy comparison section.
pub(super) const JWT_POLICY_REVIEW_COMPARISON_SCHEMA: &str =
    "termivar-jwt-policy-review-comparison/v1";
/// Additive, display-only control-reference mapping comparison section.
pub(super) const CONTROL_REFERENCE_MAPPING_COMPARISON_SCHEMA: &str =
    "termivar-control-reference-mapping-comparison/v1";
/// Additive, display-only local reconnaissance snapshot comparison section.
pub(super) const RECON_SNAPSHOT_IMPORT_COMPARISON_SCHEMA: &str =
    "termivar-recon-snapshot-import-comparison/v1";
/// Additive, display-only Cert Spotter provider comparison section.
pub(super) const RECON_CERTSPOTTER_COMPARISON_SCHEMA: &str =
    "termivar-recon-certspotter-comparison/v1";
/// Additive, display-only WordPress comparison section carried by comparison v1.
pub(super) const WORDPRESS_COMPARISON_SCHEMA_V1: &str = "termivar-wordpress-review-comparison/v1";
pub(super) const WORDPRESS_COMPARISON_SCHEMA_V2: &str = "termivar-wordpress-review-comparison/v2";
pub(super) const WORDPRESS_COMPARISON_SCHEMA_V3: &str = "termivar-wordpress-review-comparison/v3";
pub(super) const WORDPRESS_COMPARISON_SCHEMA_V4: &str = "termivar-wordpress-review-comparison/v4";
const WORDPRESS_DISCOVERY_OBSERVATION_CAPABILITY: &str =
    "technology.wordpress-metadata-source-response-observed@1";
/// Each input is bounded by the existing renderer's byte ceiling.
pub const MAX_COMPARISON_INPUT_BYTES: usize = super::MAX_RENDERED_REPORT_BYTES;

/// Supported offline comparison encodings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ComparisonFormat {
    /// Inert Markdown, with untrusted text encoded in code spans.
    Markdown,
    /// Structured JSON with all four comparison groups.
    Json,
    /// Self-contained HTML with an offline readable fallback.
    Html,
}

/// Bounded errors that never include input documents, strings, or file paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ComparisonError {
    /// An input exceeded the existing renderer's byte bound.
    InputLimitExceeded,
    /// JSON syntax, duplicate keys, nesting, or structural bounds were invalid.
    InvalidJson,
    /// A supported document contained invalid or inconsistent fields.
    InvalidDocument,
    /// The document is not a supported completed rendered assessment.
    UnsupportedDocument,
    /// Repeated or conflicting stable identities cannot be paired safely.
    AmbiguousIdentity,
    /// The complete escaped comparison would exceed its output bound.
    OutputLimitExceeded,
    /// A display-only projection could not be encoded.
    Serialization,
}

/// Bounded, display-only metadata imported from one supported assessment.
///
/// This summary proves only that the supplied bytes satisfy the current
/// rendered-assessment wire contract. It does not authenticate the producer,
/// establish target scope, or create runtime evidence or assessment authority.
/// The fields remain private and this type intentionally implements neither
/// `Serialize` nor `Deserialize`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ImportedAssessmentSummary {
    schema: String,
    profile: String,
    status: String,
    subject_count: u64,
    item_count: u64,
}

impl ImportedAssessmentSummary {
    /// Returns the exact supported rendered-assessment schema identifier.
    pub fn schema(&self) -> &str {
        &self.schema
    }

    /// Returns the validated profile declared by the imported document.
    pub fn profile(&self) -> &str {
        &self.profile
    }

    /// Returns the validated completion status declared by the document.
    pub fn status(&self) -> &str {
        &self.status
    }

    /// Returns the bounded declared subject count.
    pub const fn subject_count(&self) -> u64 {
        self.subject_count
    }

    /// Returns the bounded declared assessment-item count.
    pub const fn item_count(&self) -> u64 {
        self.item_count
    }
}

impl fmt::Display for ComparisonError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InputLimitExceeded => "comparison input exceeds the byte limit",
            Self::InvalidJson => "comparison input is not valid bounded JSON",
            Self::InvalidDocument => "comparison input has invalid or inconsistent fields",
            Self::UnsupportedDocument => {
                "comparison requires supported complete assessment documents"
            },
            Self::AmbiguousIdentity => "comparison input contains ambiguous item identities",
            Self::OutputLimitExceeded => "comparison output exceeds the byte limit",
            Self::Serialization => "comparison output could not be serialized",
        })
    }
}

impl Error for ComparisonError {}

impl From<ReportError> for ComparisonError {
    fn from(error: ReportError) -> Self {
        match error {
            ReportError::OutputLimitExceeded { .. } => Self::OutputLimitExceeded,
            ReportError::Serialization => Self::Serialization,
        }
    }
}

/// Compares two complete rendered assessment JSON byte strings, without I/O.
///
/// The caller must independently decide that comparing the scopes is appropriate.
/// The result labels scope as operator-declared: neither parsing nor matching
/// authenticates the source or establishes equivalent coverage. Imported claim
/// labels remain unendorsed text. A missing item does not mean fixed or resolved.
///
/// Matching uses the existing exact fingerprint and compatible capability ID.
/// Local reference renumbering and JSON ordering are not changes. All four
/// groups are mutually exclusive and deterministic; failure returns no partial
/// output. No authoritative runtime model is deserialized or constructed.
pub fn compare_reports(
    before: &[u8],
    after: &[u8],
    format: ComparisonFormat,
) -> Result<String, ComparisonError> {
    let document = compare_documents(import::parse(before)?, import::parse(after)?)?;
    render(&document, format, super::MAX_RENDERED_REPORT_BYTES)
}

/// Imports one complete rendered assessment into a narrow display-only summary.
///
/// Parsing uses the same strict byte, nesting, duplicate-key, field, item, and
/// optional-audit validation as [`compare_reports`]. No authoritative runtime
/// model is deserialized or constructed, and no raw item or audit content is
/// exposed to the caller.
pub fn import_assessment_summary(
    bytes: &[u8],
) -> Result<ImportedAssessmentSummary, ComparisonError> {
    let imported = import::parse(bytes)?;
    Ok(ImportedAssessmentSummary {
        schema: imported.metadata.schema,
        profile: imported.metadata.profile,
        status: imported.metadata.status,
        subject_count: imported.metadata.subject_count,
        item_count: imported.metadata.item_count,
    })
}

#[derive(Debug, Serialize)]
pub(super) struct ComparisonDocument {
    pub(super) schema: &'static str,
    pub(super) scope_assurance: &'static str,
    pub(super) coverage_equivalence: &'static str,
    pub(super) source_authenticity: &'static str,
    pub(super) interpretation_limits: [&'static str; 4],
    pub(super) before: SourceMetadata,
    pub(super) after: SourceMetadata,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) supplied_session_comparison: Option<SuppliedSessionComparison>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) secret_exposure_comparison: Option<SecretExposureComparison>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) tls_observation_comparison: Option<TlsObservationComparison>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) jwt_policy_review_comparison: Option<JwtPolicyReviewComparison>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) control_reference_mapping_comparison: Option<ControlReferenceMappingComparison>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) recon_snapshot_import_comparison: Option<ReconSnapshotImportComparison>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) recon_certspotter_comparison: Option<ReconCertSpotterComparison>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) wordpress_review_comparison: Option<WordPressReviewComparison>,
    pub(super) only_in_after: Vec<ComparisonItem>,
    pub(super) only_in_before: Vec<ComparisonItem>,
    pub(super) changed: Vec<ComparisonItem>,
    pub(super) unchanged: Vec<ComparisonItem>,
}

#[derive(Debug, Serialize)]
pub(super) struct SuppliedSessionComparison {
    pub(super) schema: &'static str,
    pub(super) status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) reason: Option<&'static str>,
    pub(super) scope_assurance: &'static str,
    pub(super) context: WordPressFacetComparison,
    pub(super) health_and_coverage: WordPressFacetComparison,
    pub(super) accounting: WordPressFacetComparison,
    pub(super) interpretation_limits: [&'static str; 5],
}

#[derive(Debug, Serialize)]
pub(super) struct SecretExposureComparison {
    pub(super) schema: &'static str,
    pub(super) status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) reason: Option<&'static str>,
    pub(super) methodology: WordPressFacetComparison,
    pub(super) coverage: WordPressFacetComparison,
    pub(super) interpretation_limits: [&'static str; 4],
}

#[derive(Debug, Serialize)]
pub(super) struct TlsObservationComparison {
    pub(super) schema: &'static str,
    pub(super) status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) reason: Option<&'static str>,
    pub(super) methodology: WordPressFacetComparison,
    pub(super) coverage: WordPressFacetComparison,
    pub(super) certificate_observations: WordPressFacetComparison,
    pub(super) interpretation_limits: [&'static str; 5],
}

#[derive(Debug, Serialize)]
pub(super) struct JwtPolicyReviewComparison {
    pub(super) schema: &'static str,
    pub(super) status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) reason: Option<&'static str>,
    pub(super) methodology: WordPressFacetComparison,
    pub(super) coverage: WordPressFacetComparison,
    pub(super) outcome: WordPressFacetComparison,
    pub(super) interpretation_limits: [&'static str; 6],
    #[serde(skip)]
    pub(super) target_selected: bool,
}

#[derive(Debug, Serialize)]
pub(super) struct ControlReferenceMappingComparison {
    pub(super) schema: &'static str,
    pub(super) status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) reason: Option<&'static str>,
    pub(super) methodology: WordPressFacetComparison,
    pub(super) coverage: WordPressFacetComparison,
    pub(super) reference_set: WordPressFacetComparison,
    pub(super) interpretation_limits: [&'static str; 5],
}

#[derive(Debug, Serialize)]
pub(super) struct ReconSnapshotImportComparison {
    pub(super) schema: &'static str,
    pub(super) status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) reason: Option<&'static str>,
    pub(super) methodology: WordPressFacetComparison,
    pub(super) provenance_and_sources: WordPressFacetComparison,
    pub(super) coverage_and_accounting: WordPressFacetComparison,
    pub(super) hypotheses: WordPressFacetComparison,
    pub(super) interpretation_limits: [&'static str; 6],
}

#[derive(Debug, Serialize)]
pub(super) struct ReconCertSpotterComparison {
    pub(super) schema: &'static str,
    pub(super) status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) reason: Option<&'static str>,
    pub(super) provider: WordPressFacetComparison,
    pub(super) methodology: WordPressFacetComparison,
    pub(super) coverage: WordPressFacetComparison,
    pub(super) hypotheses: WordPressFacetComparison,
    pub(super) interpretation_limits: [&'static str; 6],
}

#[derive(Debug, Serialize)]
pub(super) struct WordPressReviewComparison {
    pub(super) schema: &'static str,
    pub(super) status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) reason: Option<&'static str>,
    pub(super) scope_assurance: &'static str,
    pub(super) coverage: WordPressFacetComparison,
    pub(super) methodology: WordPressFacetComparison,
    pub(super) provenance: WordPressFacetComparison,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) discovery_source_content: Option<WordPressFacetComparison>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) asset_fingerprints: Option<WordPressAssetFingerprintComparison>,
    pub(super) components: WordPressEntityChanges<WordPressComponentKey>,
    pub(super) advisories: WordPressEntityChanges<WordPressAdvisoryKey>,
    pub(super) interpretation_limits: [&'static str; 6],
}

#[derive(Debug, Serialize)]
pub(super) struct WordPressAssetFingerprintComparison {
    pub(super) status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) reason: Option<&'static str>,
    pub(super) methodology: WordPressFacetComparison,
    pub(super) catalogue: WordPressFacetComparison,
    pub(super) coverage: WordPressFacetComparison,
    pub(super) resources: WordPressEntityChanges<WordPressAssetFingerprintResourceKey>,
    pub(super) components: WordPressEntityChanges<WordPressAssetFingerprintComponentKey>,
    pub(super) interpretation_limits: [&'static str; 5],
}

#[derive(Debug, Serialize)]
pub(super) struct WordPressFacetComparison {
    pub(super) status: String,
    pub(super) changed_fields: Vec<String>,
    pub(super) before: Option<Value>,
    pub(super) after: Option<Value>,
    pub(super) note: &'static str,
}

#[derive(Debug, Serialize)]
pub(super) struct WordPressEntityChanges<K> {
    pub(super) paired_unchanged_count: usize,
    pub(super) paired_changed: Vec<WordPressEntityChange<K>>,
    pub(super) only_in_before: Vec<WordPressOneSidedEntity<K>>,
    pub(super) only_in_after: Vec<WordPressOneSidedEntity<K>>,
}

impl<K> Default for WordPressEntityChanges<K> {
    fn default() -> Self {
        Self {
            paired_unchanged_count: 0,
            paired_changed: Vec::new(),
            only_in_before: Vec::new(),
            only_in_after: Vec::new(),
        }
    }
}

#[derive(Debug, Serialize)]
pub(super) struct WordPressEntityChange<K> {
    pub(super) key: K,
    pub(super) changed_dimensions: Vec<String>,
    pub(super) before: BTreeMap<String, Value>,
    pub(super) after: BTreeMap<String, Value>,
}

#[derive(Debug, Serialize)]
pub(super) struct WordPressOneSidedEntity<K> {
    pub(super) key: K,
    pub(super) content: BTreeMap<String, Value>,
    pub(super) interpretation: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub(super) struct WordPressComponentKey {
    pub(super) kind: String,
    pub(super) slug: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub(super) struct WordPressAdvisoryKey {
    pub(super) source_kind: String,
    pub(super) source_namespace: String,
    pub(super) upstream_id: String,
    pub(super) component: WordPressComponentKey,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub(super) struct WordPressAssetFingerprintResourceKey {
    pub(super) source_namespace: String,
    pub(super) component: WordPressComponentKey,
    pub(super) relative_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub(super) struct WordPressAssetFingerprintComponentKey {
    pub(super) source_namespace: String,
    pub(super) component: WordPressComponentKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ImportedWordPressAssetFingerprintAudit {
    pub(super) methodology: Value,
    pub(super) catalogue: Value,
    pub(super) coverage: Value,
    pub(super) resources: BTreeMap<WordPressAssetFingerprintResourceKey, BTreeMap<String, Value>>,
    pub(super) components: BTreeMap<WordPressAssetFingerprintComponentKey, BTreeMap<String, Value>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ImportedSuppliedSessionAudit {
    pub(super) context: Value,
    pub(super) health_and_coverage: Value,
    pub(super) accounting: Value,
    /// Exact value-safe resource/evidence bindings retained only so another
    /// strict saved-audit reader can prove it refers to the same committed
    /// supplied-session resources. These values never become runtime authority.
    pub(super) resources: BTreeMap<String, SuppliedSessionResourceBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ImportedSecretExposureAudit {
    pub(super) methodology: Value,
    pub(super) coverage: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ImportedTlsObservationAudit {
    pub(super) methodology: Value,
    pub(super) coverage: Value,
    pub(super) certificate_observations: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ImportedJwtPolicyReviewAudit {
    pub(super) schema: String,
    pub(super) methodology: Value,
    pub(super) coverage: Value,
    pub(super) outcome: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ImportedControlReferenceMappingAudit {
    pub(super) methodology: Value,
    pub(super) coverage: Value,
    pub(super) reference_set: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ImportedReconSnapshotAudit {
    pub(super) methodology: Value,
    pub(super) provenance_and_sources: Value,
    pub(super) coverage_and_accounting: Value,
    pub(super) hypotheses: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ImportedReconCertSpotterAudit {
    pub(super) provider: Value,
    pub(super) methodology: Value,
    pub(super) coverage: Value,
    pub(super) hypotheses: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SuppliedSessionResourceBinding {
    pub(super) evidence_reference: Option<String>,
    pub(super) response_bytes: u64,
    pub(super) epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ImportedWordPressAudit {
    /// Opaque deployment-aware application identity; absent from legacy audits.
    pub(super) application_reference: Option<String>,
    pub(super) coverage: Value,
    pub(super) inventory_coverage_recorded: bool,
    pub(super) methodology: Value,
    pub(super) provenance: Value,
    pub(super) discovery_source_content: Option<Value>,
    /// Present only for discovery audit v4 after its references have been
    /// cross-linked to the root supplied-session audit.
    pub(super) supplied_session_context: Option<Value>,
    pub(super) asset_fingerprints: Option<ImportedWordPressAssetFingerprintAudit>,
    pub(super) components: BTreeMap<WordPressComponentKey, BTreeMap<String, Value>>,
    pub(super) advisories: BTreeMap<WordPressAdvisoryKey, BTreeMap<String, Value>>,
}

#[derive(Debug, Serialize)]
pub(super) struct SourceMetadata {
    pub(super) sha256: String,
    pub(super) schema: String,
    pub(super) source_schema: String,
    pub(super) run_schema: String,
    pub(super) profile_schema: String,
    pub(super) profile: String,
    pub(super) status: String,
    pub(super) subject_count: u64,
    pub(super) item_count: u64,
    pub(super) optional_audits: BTreeMap<String, Value>,
}

#[derive(Debug, Serialize)]
pub(super) struct ComparisonItem {
    pub(super) fingerprint: String,
    pub(super) capability_id: String,
    pub(super) before: Option<ItemProjection>,
    pub(super) after: Option<ItemProjection>,
    pub(super) changed_fields: Vec<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct ItemProjection {
    pub(super) title: String,
    pub(super) category: String,
    pub(super) disposition: String,
    pub(super) claim_basis: String,
    pub(super) severity: Option<String>,
    pub(super) cwe: Option<String>,
    pub(super) confidence_ppm: u32,
    pub(super) redacted_summary: String,
    pub(super) remediation: RemediationProjection,
    pub(super) evidence: EvidenceMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct RemediationProjection {
    pub(super) id: String,
    pub(super) summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct EvidenceMetadata {
    pub(super) evidence_count: u64,
    pub(super) evidence_reference_count: usize,
    pub(super) control_reference_count: usize,
    pub(super) candidate_reference_count: usize,
    pub(super) case_present: bool,
    pub(super) outcome_present: bool,
    pub(super) verification_stage: Option<String>,
}

struct ImportedDocument {
    metadata: SourceMetadata,
    items: BTreeMap<String, ImportedItem>,
    supplied_session: Option<ImportedSuppliedSessionAudit>,
    secret_exposure: Option<ImportedSecretExposureAudit>,
    tls_observation: Option<ImportedTlsObservationAudit>,
    jwt_policy_review: Option<ImportedJwtPolicyReviewAudit>,
    control_reference_mapping: Option<ImportedControlReferenceMappingAudit>,
    recon_snapshot_import: Option<ImportedReconSnapshotAudit>,
    recon_certspotter: Option<ImportedReconCertSpotterAudit>,
    wordpress_review: Option<ImportedWordPressAudit>,
}

struct ImportedItem {
    capability_id: String,
    projection: ItemProjection,
    observation_evidence_references: BTreeSet<String>,
}

fn compare_documents(
    before: ImportedDocument,
    mut after: ImportedDocument,
) -> Result<ComparisonDocument, ComparisonError> {
    let block_item_pairing = !supplied_session_context_allows_item_pairing(
        before.supplied_session.as_ref(),
        after.supplied_session.as_ref(),
    );
    let supplied_session_comparison = compare_supplied_sessions(
        before.supplied_session.as_ref(),
        after.supplied_session.as_ref(),
    );
    let secret_exposure_comparison = compare_secret_exposure(
        before.secret_exposure.as_ref(),
        after.secret_exposure.as_ref(),
    );
    let tls_observation_comparison = compare_tls_observation(
        before.tls_observation.as_ref(),
        after.tls_observation.as_ref(),
    );
    let jwt_policy_review_comparison = compare_jwt_policy_review(
        before.jwt_policy_review.as_ref(),
        after.jwt_policy_review.as_ref(),
    );
    let control_reference_mapping_comparison = compare_control_reference_mapping(
        before.control_reference_mapping.as_ref(),
        after.control_reference_mapping.as_ref(),
    );
    let recon_snapshot_import_comparison = compare_recon_snapshot_import(
        before.recon_snapshot_import.as_ref(),
        after.recon_snapshot_import.as_ref(),
    );
    let recon_certspotter_comparison = compare_recon_certspotter(
        before.recon_certspotter.as_ref(),
        after.recon_certspotter.as_ref(),
    );
    let wordpress_review_comparison = compare_wordpress_reviews(
        before.wordpress_review.as_ref(),
        after.wordpress_review.as_ref(),
    );
    let mut document = ComparisonDocument {
        schema: COMPARISON_DOCUMENT_SCHEMA,
        scope_assurance: "operator-declared",
        coverage_equivalence: "not-established",
        source_authenticity: "not-established-by-parsing",
        interpretation_limits: [
            "Imported dispositions and claim bases are untrusted source labels, not endorsed findings.",
            "Only in before does not mean fixed or resolved.",
            "Only in after does not establish when an observation first appeared.",
            "Unchanged means equal compared item projections, not equivalent coverage or security.",
        ],
        before: before.metadata,
        after: after.metadata,
        supplied_session_comparison,
        secret_exposure_comparison,
        tls_observation_comparison,
        jwt_policy_review_comparison,
        control_reference_mapping_comparison,
        recon_snapshot_import_comparison,
        recon_certspotter_comparison,
        wordpress_review_comparison,
        only_in_after: Vec::new(),
        only_in_before: Vec::new(),
        changed: Vec::new(),
        unchanged: Vec::new(),
    };
    for (fingerprint, old) in before.items {
        if !block_item_pairing {
            if let Some(new) = after.items.remove(&fingerprint) {
                if old.capability_id != new.capability_id {
                    return Err(ComparisonError::AmbiguousIdentity);
                }
                let changed_fields = changed_fields(&old.projection, &new.projection);
                let item = ComparisonItem {
                    fingerprint,
                    capability_id: old.capability_id,
                    before: Some(old.projection),
                    after: Some(new.projection),
                    changed_fields,
                };
                if item.changed_fields.is_empty() {
                    document.unchanged.push(item);
                } else {
                    document.changed.push(item);
                }
                continue;
            }
        }
        document.only_in_before.push(ComparisonItem {
            fingerprint,
            capability_id: old.capability_id,
            before: Some(old.projection),
            after: None,
            changed_fields: Vec::new(),
        });
    }
    for (fingerprint, new) in after.items {
        document.only_in_after.push(ComparisonItem {
            fingerprint,
            capability_id: new.capability_id,
            before: None,
            after: Some(new.projection),
            changed_fields: Vec::new(),
        });
    }
    Ok(document)
}

fn supplied_session_context_allows_item_pairing(
    before: Option<&ImportedSuppliedSessionAudit>,
    after: Option<&ImportedSuppliedSessionAudit>,
) -> bool {
    match (before, after) {
        (None, None) => true,
        (Some(before), Some(after)) => before.context == after.context,
        (Some(_), None) | (None, Some(_)) => false,
    }
}

fn compare_supplied_sessions(
    before: Option<&ImportedSuppliedSessionAudit>,
    after: Option<&ImportedSuppliedSessionAudit>,
) -> Option<SuppliedSessionComparison> {
    if before.is_none() && after.is_none() {
        return None;
    }
    let (status, reason, context_status, facet_status) = match (before, after) {
        (Some(before), Some(after)) if before.context == after.context => (
            "compared_within_same_declared_context",
            None,
            "same_declared_context",
            None,
        ),
        (Some(before), Some(after)) => {
            let application_changed = before.context.get("application_reference")
                != after.context.get("application_reference");
            let policy_changed =
                before.context.get("policy_reference") != after.context.get("policy_reference");
            let principal_alias_changed =
                before.context.get("principal_alias") != after.context.get("principal_alias");
            let reason = if application_changed {
                "application_scope_changed"
            } else if policy_changed {
                "session_policy_changed"
            } else if principal_alias_changed {
                "operator_declared_principal_changed"
            } else {
                "declared_session_context_changed"
            };
            ("not_compared", Some(reason), reason, Some("not_comparable"))
        },
        (Some(_), None) => (
            "not_compared",
            Some("after_audit_missing"),
            "audit_presence_changed",
            Some("not_comparable"),
        ),
        (None, Some(_)) => (
            "not_compared",
            Some("before_audit_missing"),
            "audit_presence_changed",
            Some("not_comparable"),
        ),
        (None, None) => return None,
    };
    let health_status = facet_status.unwrap_or_else(|| {
        paired_status(
            before.map(|audit| &audit.health_and_coverage),
            after.map(|audit| &audit.health_and_coverage),
        )
    });
    let accounting_status = facet_status.unwrap_or_else(|| {
        paired_status(
            before.map(|audit| &audit.accounting),
            after.map(|audit| &audit.accounting),
        )
    });
    Some(SuppliedSessionComparison {
        schema: SUPPLIED_SESSION_COMPARISON_SCHEMA,
        status,
        reason,
        scope_assurance: "operator_declared",
        context: facet(
            before.map(|audit| &audit.context),
            after.map(|audit| &audit.context),
            context_status,
            "Equal opaque references represent the same supplied declarations within these files; they do not authenticate a principal, application, policy source, or cross-run identity.",
        ),
        health_and_coverage: facet(
            before.map(|audit| &audit.health_and_coverage),
            after.map(|audit| &audit.health_and_coverage),
            health_status,
            "Checkpoint and resource coverage differences can result from session loss, interruption, or policy context; they are not installation change, vulnerability change, or remediation evidence.",
        ),
        accounting: facet(
            before.map(|audit| &audit.accounting),
            after.map(|audit| &audit.accounting),
            accounting_status,
            "Counts and bytes describe bounded committed activity in each supplied audit; equality does not establish equivalent authenticated coverage.",
        ),
        interpretation_limits: [
            "The principal reference is a generic V1 slot with operator-declared assurance, not authenticated or cross-run principal identity.",
            "Policy and application digests identify declared values; they do not authenticate the target, source, account, role, or tenant.",
            "Different contexts are not paired as target changes, and missing or reduced coverage is not remediation.",
            "Health checkpoints establish only their recorded predicate at bounded moments, not continuous authentication.",
            "Exploit execution, impact validation, automatic refresh, and anonymous fallback were not performed by this audit.",
        ],
    })
}

fn compare_secret_exposure(
    before: Option<&ImportedSecretExposureAudit>,
    after: Option<&ImportedSecretExposureAudit>,
) -> Option<SecretExposureComparison> {
    if before.is_none() && after.is_none() {
        return None;
    }
    let (status, reason) = match (before, after) {
        (Some(_), Some(_)) => ("compared", None),
        (Some(_), None) => ("not_comparable", Some("after_audit_missing")),
        (None, Some(_)) => ("not_comparable", Some("before_audit_missing")),
        (None, None) => return None,
    };
    Some(SecretExposureComparison {
        schema: SECRET_EXPOSURE_COMPARISON_SCHEMA,
        status,
        reason,
        methodology: facet(
            before.map(|audit| &audit.methodology),
            after.map(|audit| &audit.methodology),
            paired_status(
                before.map(|audit| &audit.methodology),
                after.map(|audit| &audit.methodology),
            ),
            "Catalogue, policy, representation, context, or inspection-limit changes are methodology changes; they do not establish a target change.",
        ),
        coverage: facet(
            before.map(|audit| &audit.coverage),
            after.map(|audit| &audit.coverage),
            paired_status(
                before.map(|audit| &audit.coverage),
                after.map(|audit| &audit.coverage),
            ),
            "Missing or reduced response, byte, outcome, or observation coverage is not remediation, secret absence, or proof of safety.",
        ),
        interpretation_limits: [
            "The fixed detector catalogue reports bounded secret-shaped response observations; it does not validate ownership, permissions, or provider acceptance.",
            "No raw matched value or public secret hash is imported into this display-only comparison.",
            "A one-sided observation does not establish when exposure began or ended, and disappearance is not remediation.",
            "Source authentication, secret validity, exploit execution, and impact validation are not established by this audit.",
        ],
    })
}

fn compare_tls_observation(
    before: Option<&ImportedTlsObservationAudit>,
    after: Option<&ImportedTlsObservationAudit>,
) -> Option<TlsObservationComparison> {
    if before.is_none() && after.is_none() {
        return None;
    }
    let (status, reason) = match (before, after) {
        (Some(_), Some(_)) => ("compared", None),
        (Some(_), None) => ("not_comparable", Some("after_audit_missing")),
        (None, Some(_)) => ("not_comparable", Some("before_audit_missing")),
        (None, None) => return None,
    };
    Some(TlsObservationComparison {
        schema: TLS_OBSERVATION_COMPARISON_SCHEMA,
        status,
        reason,
        methodology: facet(
            before.map(|audit| &audit.methodology),
            after.map(|audit| &audit.methodology),
            paired_status(
                before.map(|audit| &audit.methodology),
                after.map(|audit| &audit.methodology),
            ),
            "Policy, target scheme, backend visibility, validation scope, or active-matrix selection changes are methodology changes; they are not vulnerability, hardening, or remediation evidence.",
        ),
        coverage: facet(
            before.map(|audit| &audit.coverage),
            after.map(|audit| &audit.coverage),
            paired_status(
                before.map(|audit| &audit.coverage),
                after.map(|audit| &audit.coverage),
            ),
            "Assessment-request, response, retention, first-observation-time, validity-at-observation, and occurrence-count changes describe observation coverage; fewer observations do not establish a certificate removal or remediation.",
        ),
        certificate_observations: facet(
            before.map(|audit| &audit.certificate_observations),
            after.map(|audit| &audit.certificate_observations),
            paired_status(
                before.map(|audit| &audit.certificate_observations),
                after.map(|audit| &audit.certificate_observations),
            ),
            "Leaf digest, byte length, declared validity bounds, and SAN-count changes are stable certificate-observation differences only; they do not authenticate a source or enumerate TLS support.",
        ),
        interpretation_limits: [
            "The audit describes leaf bytes exposed by successful existing response connections; it does not enumerate all server protocols, cipher suites, certificates, chains, or handshakes.",
            "The current backend does not expose negotiated protocol, negotiated cipher suite, ALPN, full chain, connection reuse, session resumption, or resumed-versus-full handshake state.",
            "Standard transport validation is scoped to a successful response connection and is not source authentication, a fresh signature check by this report, or worldwide trust.",
            "Revocation, AIA, CRL, OCSP, certificate-transparency, and active negotiation retrieval were not performed.",
            "A one-sided or changed certificate observation does not establish vulnerability, exploitation, impact, rotation quality, or remediation.",
        ],
    })
}

fn compare_jwt_policy_review(
    before: Option<&ImportedJwtPolicyReviewAudit>,
    after: Option<&ImportedJwtPolicyReviewAudit>,
) -> Option<JwtPolicyReviewComparison> {
    if before.is_none() && after.is_none() {
        return None;
    }
    let (status, reason) = match (before, after) {
        (Some(before), Some(after)) if before.schema == after.schema => ("compared", None),
        (Some(_), Some(_)) => ("not_comparable", Some("audit_schema_changed")),
        (Some(_), None) => ("not_comparable", Some("after_audit_missing")),
        (None, Some(_)) => ("not_comparable", Some("before_audit_missing")),
        (None, None) => return None,
    };
    let target_selected = before
        .into_iter()
        .chain(after)
        .any(|audit| audit.schema == "security.jwt-policy-review-audit/v2");
    let methodology_status = if status == "compared" {
        paired_status(
            before.map(|audit| &audit.methodology),
            after.map(|audit| &audit.methodology),
        )
    } else {
        "not_comparable"
    };
    let coverage_status = if status == "compared" {
        paired_status(
            before.map(|audit| &audit.coverage),
            after.map(|audit| &audit.coverage),
        )
    } else {
        "not_comparable"
    };
    let outcome_status = if status == "compared" {
        paired_status(
            before.map(|audit| &audit.outcome),
            after.map(|audit| &audit.outcome),
        )
    } else {
        "not_comparable"
    };
    Some(JwtPolicyReviewComparison {
        schema: JWT_POLICY_REVIEW_COMPARISON_SCHEMA,
        status,
        reason,
        methodology: facet(
            before.map(|audit| &audit.methodology),
            after.map(|audit| &audit.methodology),
            methodology_status,
            "Declared policy reference/revision, expected-claim selection, clock-skew allowance, or exact public-key-byte identity changes can change interpretation without any target behavior changing.",
        ),
        coverage: facet(
            before.map(|audit| &audit.coverage),
            after.map(|audit| &audit.coverage),
            coverage_status,
            if target_selected {
                "The local evaluation instant plus bounded target dispatch, commit, retained-byte, and exact transport-byte accounting describe coverage. Charged chunk overrun can exceed retained bytes; missing or changed coverage is not a target fix, regression, or authorization result."
            } else {
                "The local evaluation instant and explicit absence of external activity describe bounded review coverage; they do not establish continuous clock accuracy or target acceptance."
            },
        ),
        outcome: facet(
            before.map(|audit| &audit.outcome),
            after.map(|audit| &audit.outcome),
            outcome_status,
            if target_selected {
                "Local parsing, policy consistency, signature verification, target marker controls, and authorization effect are distinct. A changed marker relationship remains review-level and does not establish a general bypass or impact."
            } else {
                "Parsing, local policy consistency, and local signature status are separate outcomes. A changed local outcome is not evidence that a target accepted a token or that authorization changed."
            },
        ),
        interpretation_limits: if target_selected {
            [
                "The compact token, claim names and values, signature bytes, selected marker name, raw resource URL, and verification-key material are not imported into this display-only comparison.",
                "The operator policy revision must change when private policy semantics change; public digests and opaque references authenticate neither key, target, policy, nor source.",
                "Local parsing does not authenticate claims; local signature verification applies only to the explicitly supplied local public key.",
                "A target marker relationship applies only to the selected resource and matched controls; it is not a confirmed bypass, authorization effect, exploitability, or impact.",
                "A v1 local-only audit and a v2 target-selected audit are not comparable; the target selection is a methodology and coverage change.",
                "A one-sided or changed audit does not establish vulnerability, remediation, or source authenticity.",
            ]
        } else {
            [
                "The compact token, claim names and values, signature bytes, and verification-key material are not imported into this display-only comparison.",
                "The operator policy revision must change when private policy semantics change; the public-key SHA-256 identifies bytes but authenticates neither key nor source.",
                "Local parsing does not authenticate claims; local signature verification applies only to the explicitly supplied local public key.",
                "Policy consistency is not target acceptance, authorization, exploitability, or impact.",
                "The evaluator performed no target request, token forwarding, or remote-key retrieval.",
                "A one-sided or changed audit does not establish vulnerability, remediation, or source authenticity.",
            ]
        },
        target_selected,
    })
}

fn compare_control_reference_mapping(
    before: Option<&ImportedControlReferenceMappingAudit>,
    after: Option<&ImportedControlReferenceMappingAudit>,
) -> Option<ControlReferenceMappingComparison> {
    if before.is_none() && after.is_none() {
        return None;
    }
    let (status, reason) = match (before, after) {
        (Some(_), Some(_)) => ("compared", None),
        (Some(_), None) => ("not_comparable", Some("after_audit_missing")),
        (None, Some(_)) => ("not_comparable", Some("before_audit_missing")),
        (None, None) => return None,
    };
    Some(ControlReferenceMappingComparison {
        schema: CONTROL_REFERENCE_MAPPING_COMPARISON_SCHEMA,
        status,
        reason,
        methodology: facet(
            before.map(|audit| &audit.methodology),
            after.map(|audit| &audit.methodology),
            paired_status(
                before.map(|audit| &audit.methodology),
                after.map(|audit| &audit.methodology),
            ),
            "Policy, catalogue revision, reviewed-source revision, rights posture, external-activity declaration, or claim-limit changes are methodology changes; they do not establish a target change, vulnerability, remediation, or control result.",
        ),
        coverage: facet(
            before.map(|audit| &audit.coverage),
            after.map(|audit| &audit.coverage),
            paired_status(
                before.map(|audit| &audit.coverage),
                after.map(|audit| &audit.coverage),
            ),
            "Mapped, unmapped, relationship, reference-link, and omission counts describe bounded mapping coverage; fewer references do not establish remediation, control fulfilment, or safety.",
        ),
        reference_set: facet(
            before.map(|audit| &audit.reference_set),
            after.map(|audit| &audit.reference_set),
            paired_status(
                before.map(|audit| &audit.reference_set),
                after.map(|audit| &audit.reference_set),
            ),
            "Catalogue/source revisions and evidence-to-reference relationships are reference-set differences. They are not target observations, introduced vulnerabilities, verified remediation, compliance, or certification.",
        ),
        interpretation_limits: [
            "The mapping is an offline, versioned reference projection over already composed assessment items; it performs no target, provider, or source-retrieval request.",
            "Framework identifiers, short titles where rights permit, and original mapping rationales provide technical review context only; they are not copied standards text or a control assessment.",
            "A mapping relationship does not establish organizational applicability, control fulfilment, compliance, certification, legal noncompliance, or source authenticity.",
            "An unmapped item means only that no exact rule in this finite catalogue matched; absence of a finding or mapping establishes no control outcome.",
            "One-sided or changed mapping audits can result from catalogue, source, methodology, coverage, or source-item changes and never by themselves prove target change or remediation.",
        ],
    })
}

fn compare_recon_snapshot_import(
    before: Option<&ImportedReconSnapshotAudit>,
    after: Option<&ImportedReconSnapshotAudit>,
) -> Option<ReconSnapshotImportComparison> {
    if before.is_none() && after.is_none() {
        return None;
    }
    let (status, reason) = match (before, after) {
        (Some(_), Some(_)) => ("compared", None),
        (Some(_), None) => ("not_comparable", Some("after_audit_missing")),
        (None, Some(_)) => ("not_comparable", Some("before_audit_missing")),
        (None, None) => return None,
    };
    Some(ReconSnapshotImportComparison {
        schema: RECON_SNAPSHOT_IMPORT_COMPARISON_SCHEMA,
        status,
        reason,
        methodology: facet(
            before.map(|audit| &audit.methodology),
            after.map(|audit| &audit.methodology),
            paired_status(
                before.map(|audit| &audit.methodology),
                after.map(|audit| &audit.methodology),
            ),
            "Parser policy, external-activity declaration, or claim-limit changes are methodology changes; exact-input identity is compared with provenance and sources. None establishes a target, vulnerability, or remediation change.",
        ),
        provenance_and_sources: facet(
            before.map(|audit| &audit.provenance_and_sources),
            after.map(|audit| &audit.provenance_and_sources),
            paired_status(
                before.map(|audit| &audit.provenance_and_sources),
                after.map(|audit| &audit.provenance_and_sources),
            ),
            "Snapshot identity and source declarations are operator-supplied provenance. Differences do not authenticate either source, establish freshness, or authorize scanning a named asset.",
        ),
        coverage_and_accounting: facet(
            before.map(|audit| &audit.coverage_and_accounting),
            after.map(|audit| &audit.coverage_and_accounting),
            paired_status(
                before.map(|audit| &audit.coverage_and_accounting),
                after.map(|audit| &audit.coverage_and_accounting),
            ),
            "Source, record, association, and prepared-index counts describe the bounded imported snapshot only. Equal counts do not prove equal content or complete provider coverage.",
        ),
        hypotheses: facet(
            before.map(|audit| &audit.hypotheses),
            after.map(|audit| &audit.hypotheses),
            paired_status(
                before.map(|audit| &audit.hypotheses),
                after.map(|audit| &audit.hypotheses),
            ),
            "Added, removed, or changed imported hypotheses are source-data differences, not target changes, newly discovered vulnerabilities, verified remediation, ownership, or reachability results.",
        ),
        interpretation_limits: [
            "The imported snapshot is inert local reference material and performed no target request, provider request, archive processing, or decompression.",
            "Names, addresses, service-product hints, and reputation labels remain source-qualified hypotheses and never become assessment items or broker authority.",
            "Exact-input SHA-256 identifies supplied bytes; it is not a signature, source authentication, rights verification, freshness proof, or completeness proof.",
            "A certificate name or historical DNS address does not establish current ownership, authorization, reachability, or tenant association.",
            "One-sided audit presence is not comparable and does not establish asset appearance, disappearance, vulnerability, or remediation.",
            "Hypothesis differences must be reviewed with their declared sources and limitations; they do not create a scan permit.",
        ],
    })
}

fn compare_recon_certspotter(
    before: Option<&ImportedReconCertSpotterAudit>,
    after: Option<&ImportedReconCertSpotterAudit>,
) -> Option<ReconCertSpotterComparison> {
    if before.is_none() && after.is_none() {
        return None;
    }
    let (status, reason) = match (before, after) {
        (Some(_), Some(_)) => ("compared", None),
        (Some(_), None) => ("not_comparable", Some("after_audit_missing")),
        (None, Some(_)) => ("not_comparable", Some("before_audit_missing")),
        (None, None) => return None,
    };
    Some(ReconCertSpotterComparison {
        schema: RECON_CERTSPOTTER_COMPARISON_SCHEMA,
        status,
        reason,
        provider: facet(
            before.map(|audit| &audit.provider),
            after.map(|audit| &audit.provider),
            paired_status(
                before.map(|audit| &audit.provider),
                after.map(|audit| &audit.provider),
            ),
            "Provider identity, effective origin, execution mode, query scope, or opaque policy-reference changes are provider-context differences. They do not authenticate a source, establish ownership, or authorize scanning.",
        ),
        methodology: facet(
            before.map(|audit| &audit.methodology),
            after.map(|audit| &audit.methodology),
            paired_status(
                before.map(|audit| &audit.methodology),
                after.map(|audit| &audit.methodology),
            ),
            "Endpoint, pagination, compiled-bound, no-retry, no-polling, credential, or fixed claim-limit changes are methodology differences, not target changes or security findings.",
        ),
        coverage: facet(
            before.map(|audit| &audit.coverage),
            after.map(|audit| &audit.coverage),
            paired_status(
                before.map(|audit| &audit.coverage),
                after.map(|audit| &audit.coverage),
            ),
            "Terminal state, completeness, cursor, request, byte, issuance, retention, and omission counters describe only each bounded provider collection. Equal counters do not prove equal content, currentness, or complete CT coverage.",
        ),
        hypotheses: facet(
            before.map(|audit| &audit.hypotheses),
            after.map(|audit| &audit.hypotheses),
            paired_status(
                before.map(|audit| &audit.hypotheses),
                after.map(|audit| &audit.hypotheses),
            ),
            "Added, removed, or changed source-qualified names are provider-result differences. They are not findings and do not establish ownership, authentication, currentness, reachability, or scan authority.",
        ),
        interpretation_limits: [
            "The comparison parses saved reports only; it performs no target or provider request and does not authenticate either report or provider response.",
            "Cert Spotter names remain source-qualified hypotheses and never become assessment items, findings, broker permits, or target authority.",
            "Provider exhaustion means only that an empty page was observed at the bounded cursor; it is not global CT completeness or currentness proof.",
            "A one-sided audit or hypothesis does not establish asset appearance, disappearance, ownership, reachability, vulnerability, or remediation.",
            "Transport success and TLS validation do not authenticate the provider as the asset owner or validate the returned certificate names.",
            "Every compared hypothesis retains the fixed no-authority, no-ownership, no-currentness, and no-source-authentication claim limits.",
        ],
    })
}

fn compare_wordpress_reviews(
    before: Option<&ImportedWordPressAudit>,
    after: Option<&ImportedWordPressAudit>,
) -> Option<WordPressReviewComparison> {
    if before.is_none() && after.is_none() {
        return None;
    }
    let (status, reason, compare_entities) = wordpress_comparison_scope(before, after);
    let coverage = facet(
        before.map(|audit| &audit.coverage),
        after.map(|audit| &audit.coverage),
        match (before, after) {
            (Some(left), Some(right)) if left.coverage != right.coverage => "changed",
            (Some(left), Some(right))
                if left.inventory_coverage_recorded && right.inventory_coverage_recorded =>
            {
                "same_declared_projection"
            },
            (Some(_), Some(_)) => "not_established",
            _ => "coverage_changed",
        },
        "Declared inventory and source-selection coverage only; equal values do not establish equivalent security coverage.",
    );
    let methodology = facet(
        before.map(|audit| &audit.methodology),
        after.map(|audit| &audit.methodology),
        paired_status(before.map(|audit| &audit.methodology), after.map(|audit| &audit.methodology)),
        "A methodology change can change interpretation without an installation or advisory changing.",
    );
    let provenance_status = wordpress_provenance_status(before, after);
    let provenance = facet(
        before.map(|audit| &audit.provenance),
        after.map(|audit| &audit.provenance),
        provenance_status,
        "Digests identify supplied bytes; they do not authenticate a source or prove collection completeness.",
    );
    let discovery_source_content = if before
        .is_some_and(|audit| audit.discovery_source_content.is_some())
        || after.is_some_and(|audit| audit.discovery_source_content.is_some())
    {
        Some(facet(
            before.and_then(|audit| audit.discovery_source_content.as_ref()),
            after.and_then(|audit| audit.discovery_source_content.as_ref()),
            paired_status(
                before.and_then(|audit| audit.discovery_source_content.as_ref()),
                after.and_then(|audit| audit.discovery_source_content.as_ref()),
            ),
            "REST namespace declarations and other non-component metadata are source content; changes do not by themselves establish changed security coverage.",
        ))
    } else {
        None
    };
    let asset_fingerprints = compare_wordpress_asset_fingerprints(
        before.and_then(|audit| audit.asset_fingerprints.as_ref()),
        after.and_then(|audit| audit.asset_fingerprints.as_ref()),
        status,
        reason,
        compare_entities,
    );
    let (components, advisories) =
        if let (true, Some(before), Some(after)) = (compare_entities, before, after) {
            (
                compare_wordpress_entities(&before.components, &after.components),
                compare_wordpress_entities(&before.advisories, &after.advisories),
            )
        } else {
            (
                WordPressEntityChanges::default(),
                WordPressEntityChanges::default(),
            )
        };
    Some(WordPressReviewComparison {
        schema: if before.is_some_and(|audit| audit.supplied_session_context.is_some())
            || after.is_some_and(|audit| audit.supplied_session_context.is_some())
        {
            WORDPRESS_COMPARISON_SCHEMA_V4
        } else if asset_fingerprints.is_some() {
            WORDPRESS_COMPARISON_SCHEMA_V3
        } else if discovery_source_content.is_some() {
            WORDPRESS_COMPARISON_SCHEMA_V2
        } else {
            WORDPRESS_COMPARISON_SCHEMA_V1
        },
        status,
        reason,
        scope_assurance: "operator-declared",
        coverage,
        methodology,
        provenance,
        discovery_source_content,
        asset_fingerprints,
        components,
        advisories,
        interpretation_limits: [
            "WordPress differences compare validated display-only audit projections; they do not rerun an assessment.",
            "One-sided components or advisories do not establish installation, removal, discovery time, or remediation.",
            "Simultaneous inventory, source, methodology, and applicability changes are listed without assigning cause.",
            "Applicability remains an imported declared-data result, not proof of exploitability or safety.",
            "A missing audit or reduced declaration changes coverage; it does not mean all WordPress issues disappeared.",
            "Public metadata content is compared separately from collection outcomes; neither dimension authenticates installation state.",
        ],
    })
}

fn compare_wordpress_asset_fingerprints(
    before: Option<&ImportedWordPressAssetFingerprintAudit>,
    after: Option<&ImportedWordPressAssetFingerprintAudit>,
    scope_status: &'static str,
    scope_reason: Option<&'static str>,
    compare_entities: bool,
) -> Option<WordPressAssetFingerprintComparison> {
    let (status, reason) = match (before, after) {
        (Some(_), Some(_)) if compare_entities => ("compared", None),
        (Some(_), Some(_)) => (scope_status, scope_reason),
        (Some(_), None) => ("not_compared", Some("after_fingerprint_audit_missing")),
        (None, Some(_)) => ("not_compared", Some("before_fingerprint_audit_missing")),
        (None, None) => return None,
    };
    let methodology = facet(
        before.map(|audit| &audit.methodology),
        after.map(|audit| &audit.methodology),
        paired_status(
            before.map(|audit| &audit.methodology),
            after.map(|audit| &audit.methodology),
        ),
        "Fingerprint methodology changes can change candidate sets without target resource bytes changing.",
    );
    let catalogue = facet(
        before.map(|audit| &audit.catalogue),
        after.map(|audit| &audit.catalogue),
        wordpress_fingerprint_catalogue_status(
            before.map(|audit| &audit.catalogue),
            after.map(|audit| &audit.catalogue),
        ),
        "A changed finite reference set can change candidates without an installed component or target resource changing.",
    );
    let coverage = facet(
        before.map(|audit| &audit.coverage),
        after.map(|audit| &audit.coverage),
        paired_status(
            before.map(|audit| &audit.coverage),
            after.map(|audit| &audit.coverage),
        ),
        "Unavailable or omitted resource coverage is not a component removal, clean result, or remediation.",
    );
    let (resources, components) = match (before, after, compare_entities) {
        (Some(before), Some(after), true) => (
            compare_wordpress_entities(&before.resources, &after.resources),
            compare_wordpress_entities(&before.components, &after.components),
        ),
        _ => (
            WordPressEntityChanges::default(),
            WordPressEntityChanges::default(),
        ),
    };
    Some(WordPressAssetFingerprintComparison {
        status,
        reason,
        methodology,
        catalogue,
        coverage,
        resources,
        components,
        interpretation_limits: [
            "Compared SHA-256 values and byte lengths describe complete admitted response bytes, not whole-package verification.",
            "Catalogue candidates are conditional on a finite operator-supplied reference set and are not installed-version evidence.",
            "Identical bytes can occur in unlisted releases, copied assets, caches, or custom builds.",
            "A one-sided or failed resource observation does not establish component installation, removal, or remediation.",
            "Source labels and digests identify supplied data; they do not authenticate its publisher or completeness.",
        ],
    })
}

fn wordpress_fingerprint_catalogue_status(
    before: Option<&Value>,
    after: Option<&Value>,
) -> &'static str {
    let (Some(before), Some(after)) = (before, after) else {
        return "not_comparable";
    };
    if before == after {
        return "unchanged";
    }
    let (Some(before_fields), Some(after_fields)) = (before.as_object(), after.as_object()) else {
        return "changed";
    };
    if before_fields.get("semantic_sha256") == after_fields.get("semantic_sha256")
        && fingerprint_catalogue_without_byte_identity(before)
            == fingerprint_catalogue_without_byte_identity(after)
    {
        "input_bytes_changed_without_reference_semantic_change"
    } else {
        "changed"
    }
}

fn fingerprint_catalogue_without_byte_identity(value: &Value) -> Value {
    let mut value = value.clone();
    if let Some(fields) = value.as_object_mut() {
        fields.remove("byte_length");
        fields.remove("sha256");
    }
    value
}

fn wordpress_comparison_scope(
    before: Option<&ImportedWordPressAudit>,
    after: Option<&ImportedWordPressAudit>,
) -> (&'static str, Option<&'static str>, bool) {
    let (Some(before), Some(after)) = (before, after) else {
        return if before.is_some() {
            ("not_compared", Some("after_audit_missing"), false)
        } else {
            ("not_compared", Some("before_audit_missing"), false)
        };
    };

    let application_scope = match (
        before.application_reference.as_deref(),
        after.application_reference.as_deref(),
    ) {
        (Some(before), Some(after)) if before == after => None,
        (Some(_), Some(_)) => Some("application_scope_mismatch"),
        (None, None) => None,
        _ => Some("application_scope_unknown"),
    };
    if let Some(reason) = application_scope {
        return ("not_compared", Some(reason), false);
    }
    match (
        before.supplied_session_context.as_ref(),
        after.supplied_session_context.as_ref(),
    ) {
        (Some(before), Some(after)) if before == after => ("compared", None, true),
        (Some(_), Some(_)) => (
            "not_compared",
            Some("supplied_session_context_mismatch"),
            false,
        ),
        (None, None) => ("compared", None, true),
        _ => (
            "not_compared",
            Some("supplied_session_context_unknown"),
            false,
        ),
    }
}

fn paired_status(before: Option<&Value>, after: Option<&Value>) -> &'static str {
    match (before, after) {
        (Some(before), Some(after)) if before == after => "unchanged",
        (Some(_), Some(_)) => "changed",
        _ => "not_comparable",
    }
}

fn facet(
    before: Option<&Value>,
    after: Option<&Value>,
    status: &str,
    note: &'static str,
) -> WordPressFacetComparison {
    WordPressFacetComparison {
        status: status.to_owned(),
        changed_fields: changed_value_fields(before, after),
        before: before.cloned(),
        after: after.cloned(),
        note,
    }
}

fn changed_value_fields(before: Option<&Value>, after: Option<&Value>) -> Vec<String> {
    let Some(before) = before.and_then(Value::as_object) else {
        return if before == after {
            Vec::new()
        } else {
            vec!["audit_presence".to_owned()]
        };
    };
    let Some(after) = after.and_then(Value::as_object) else {
        return vec!["audit_presence".to_owned()];
    };
    before
        .keys()
        .chain(after.keys())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter(|key| before.get(*key) != after.get(*key))
        .cloned()
        .collect()
}

fn wordpress_provenance_status(
    before: Option<&ImportedWordPressAudit>,
    after: Option<&ImportedWordPressAudit>,
) -> &'static str {
    let (Some(before), Some(after)) = (before, after) else {
        return "not_comparable";
    };
    if before.provenance == after.provenance {
        return "unchanged";
    }
    let before_input = before
        .provenance
        .get("external_input")
        .and_then(Value::as_object);
    let after_input = after
        .provenance
        .get("external_input")
        .and_then(Value::as_object);
    if let (Some(before_input), Some(after_input)) = (before_input, after_input) {
        let same_semantic_digest =
            before_input.get("semantic_sha256") == after_input.get("semantic_sha256");
        if same_semantic_digest
            && before.components == after.components
            && before.advisories == after.advisories
            && provenance_without_external_byte_identity(&before.provenance)
                == provenance_without_external_byte_identity(&after.provenance)
        {
            return "input_bytes_changed_without_selected_semantic_change";
        }
        if !same_semantic_digest
            && before.components == after.components
            && before.advisories == after.advisories
        {
            return "source_snapshot_semantics_changed_without_selected_record_change";
        }
    }
    if before.components == after.components && before.advisories == after.advisories {
        return "input_provenance_changed_semantic_significance_not_established";
    }
    "changed"
}

fn provenance_without_external_byte_identity(value: &Value) -> Value {
    let mut value = value.clone();
    if let Some(input) = value
        .get_mut("external_input")
        .and_then(Value::as_object_mut)
    {
        input.remove("byte_length");
        input.remove("sha256");
    }
    value
}

fn compare_wordpress_entities<K>(
    before: &BTreeMap<K, BTreeMap<String, Value>>,
    after: &BTreeMap<K, BTreeMap<String, Value>>,
) -> WordPressEntityChanges<K>
where
    K: Clone + Ord,
{
    let mut result = WordPressEntityChanges::default();
    let mut remaining = after.clone();
    for (key, before_content) in before {
        if let Some(after_content) = remaining.remove(key) {
            let changed_dimensions = before_content
                .keys()
                .chain(after_content.keys())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .filter(|dimension| before_content.get(*dimension) != after_content.get(*dimension))
                .cloned()
                .collect::<Vec<_>>();
            if changed_dimensions.is_empty() {
                result.paired_unchanged_count += 1;
            } else {
                result.paired_changed.push(WordPressEntityChange {
                    key: key.clone(),
                    changed_dimensions,
                    before: before_content.clone(),
                    after: after_content,
                });
            }
        } else {
            result.only_in_before.push(WordPressOneSidedEntity {
                key: key.clone(),
                content: before_content.clone(),
                interpretation:
                    "present_only_in_the_supplied_before_audit_not_verified_remediation",
            });
        }
    }
    for (key, content) in remaining {
        result.only_in_after.push(WordPressOneSidedEntity {
            key,
            content,
            interpretation: "present_only_in_the_supplied_after_audit_not_verified_newness",
        });
    }
    result
}

fn changed_fields(before: &ItemProjection, after: &ItemProjection) -> Vec<&'static str> {
    [
        ("title", before.title != after.title),
        ("category", before.category != after.category),
        ("disposition", before.disposition != after.disposition),
        ("claim_basis", before.claim_basis != after.claim_basis),
        ("severity", before.severity != after.severity),
        ("cwe", before.cwe != after.cwe),
        (
            "confidence_ppm",
            before.confidence_ppm != after.confidence_ppm,
        ),
        (
            "redacted_summary",
            before.redacted_summary != after.redacted_summary,
        ),
        ("remediation", before.remediation != after.remediation),
        ("evidence", before.evidence != after.evidence),
    ]
    .into_iter()
    .filter_map(|(name, changed)| changed.then_some(name))
    .collect()
}

fn render(
    document: &ComparisonDocument,
    format: ComparisonFormat,
    limit: usize,
) -> Result<String, ComparisonError> {
    match format {
        ComparisonFormat::Json => Ok(render_serializable_json(document, limit)?),
        ComparisonFormat::Markdown => render_markdown(document, limit),
        ComparisonFormat::Html => html::render(document, limit),
    }
}

fn render_markdown(document: &ComparisonDocument, limit: usize) -> Result<String, ComparisonError> {
    let mut output = RenderBuffer::new(limit);
    output.push_str("# Offline report comparison\n\n")?;
    output.push_str(
        "Scope is operator-declared. Coverage equivalence and source authenticity are not established. \
Imported claims are not endorsed. Only in before does not mean fixed or resolved. \
Only in after does not establish when an observation first appeared. \
Unchanged means equality of the compared projection, not proof of security.\n\n",
    )?;
    for (name, source) in [("Before", &document.before), ("After", &document.after)] {
        output.push_fmt(format_args!("## {name} source\n\n"))?;
        write_source_markdown(&mut output, source)?;
    }
    if let Some(session) = &document.supplied_session_comparison {
        write_supplied_session_comparison_markdown(&mut output, session)?;
    }
    if let Some(secret_exposure) = &document.secret_exposure_comparison {
        write_secret_exposure_comparison_markdown(&mut output, secret_exposure)?;
    }
    if let Some(tls_observation) = &document.tls_observation_comparison {
        write_tls_observation_comparison_markdown(&mut output, tls_observation)?;
    }
    if let Some(jwt_policy_review) = &document.jwt_policy_review_comparison {
        write_jwt_policy_review_comparison_markdown(&mut output, jwt_policy_review)?;
    }
    if let Some(control_reference_mapping) = &document.control_reference_mapping_comparison {
        write_control_reference_mapping_comparison_markdown(
            &mut output,
            control_reference_mapping,
        )?;
    }
    if let Some(recon_snapshot) = &document.recon_snapshot_import_comparison {
        write_recon_snapshot_import_comparison_markdown(&mut output, recon_snapshot)?;
    }
    if let Some(recon_certspotter) = &document.recon_certspotter_comparison {
        write_recon_certspotter_comparison_markdown(&mut output, recon_certspotter)?;
    }
    if let Some(wordpress) = &document.wordpress_review_comparison {
        write_wordpress_comparison_markdown(&mut output, wordpress)?;
    }
    for (name, items) in [
        ("only_in_after", &document.only_in_after),
        ("only_in_before", &document.only_in_before),
        ("changed", &document.changed),
        ("unchanged", &document.unchanged),
    ] {
        output.push_fmt(format_args!("## {name} ({})\n\n", items.len()))?;
        if items.is_empty() {
            output.push_str("No items in this group.\n\n")?;
        }
        for item in items {
            output.push_str("### Item\n\n- Fingerprint: ")?;
            write_markdown_code_span(&mut output, &item.fingerprint)?;
            output.push_str("\n- Capability: ")?;
            write_markdown_code_span(&mut output, &item.capability_id)?;
            if !item.changed_fields.is_empty() {
                output.push_str("\n- Changed fields: ")?;
                write_markdown_code_span(&mut output, &item.changed_fields.join(", "))?;
            }
            output.push_str("\n\n")?;
            if let (Some(before), Some(_)) = (&item.before, &item.after) {
                if item.changed_fields.is_empty() {
                    output.push_str("#### Shared comparable projection\n\n")?;
                    write_projection(&mut output, before)?;
                    continue;
                }
            }
            for (name, projection) in [("Before", &item.before), ("After", &item.after)] {
                output.push_fmt(format_args!("#### {name}\n\n"))?;
                if let Some(projection) = projection {
                    write_projection(&mut output, projection)?;
                } else {
                    output.push_str("Not present in this input.\n\n")?;
                }
            }
        }
    }
    Ok(output.finish())
}

fn write_supplied_session_comparison_markdown(
    output: &mut RenderBuffer,
    comparison: &SuppliedSessionComparison,
) -> Result<(), ComparisonError> {
    output.push_str("## Supplied session differences\n\n- Schema: ")?;
    write_markdown_code_span(output, comparison.schema)?;
    output.push_str("\n- Status: ")?;
    write_markdown_code_span(output, comparison.status)?;
    if let Some(reason) = comparison.reason {
        output.push_str("\n- Reason: ")?;
        write_markdown_code_span(output, reason)?;
    }
    output.push_str("\n- Scope assurance: ")?;
    write_markdown_code_span(output, comparison.scope_assurance)?;
    output.push_str(
        "\n\nThis display-only section keeps declared session context separate from health, coverage, and bounded accounting. It does not authenticate a principal or establish target change or remediation.\n\n",
    )?;
    for (label, facet) in [
        ("Declared context", &comparison.context),
        ("Health and coverage", &comparison.health_and_coverage),
        ("Accounting", &comparison.accounting),
    ] {
        output.push_fmt(format_args!("### {label}\n\n- Status: "))?;
        write_markdown_code_span(output, &facet.status)?;
        if !facet.changed_fields.is_empty() {
            output.push_str("\n- Changed fields: ")?;
            write_markdown_code_span(output, &facet.changed_fields.join(", "))?;
        }
        output.push_str("\n- Before: ")?;
        write_markdown_code_span(output, &display_json(facet.before.as_ref())?)?;
        output.push_str("\n- After: ")?;
        write_markdown_code_span(output, &display_json(facet.after.as_ref())?)?;
        output.push_str("\n- Interpretation: ")?;
        write_markdown_code_span(output, facet.note)?;
        output.push_str("\n\n")?;
    }
    output.push_str("### Interpretation limits\n\n")?;
    for limit in comparison.interpretation_limits {
        output.push_str("- ")?;
        write_markdown_code_span(output, limit)?;
        output.push_char('\n')?;
    }
    output.push_char('\n')?;
    Ok(())
}

fn write_source_markdown(
    output: &mut RenderBuffer,
    source: &SourceMetadata,
) -> Result<(), ComparisonError> {
    for (name, value) in [
        ("sha256", source.sha256.as_str()),
        ("schema", source.schema.as_str()),
        ("source_schema", source.source_schema.as_str()),
        ("run_schema", source.run_schema.as_str()),
        ("profile_schema", source.profile_schema.as_str()),
        ("profile", source.profile.as_str()),
        ("status", source.status.as_str()),
    ] {
        output.push_str("- ")?;
        write_markdown_code_span(output, name)?;
        output.push_str(": ")?;
        write_markdown_code_span(output, value)?;
        output.push_char('\n')?;
    }
    for (name, value) in [
        ("subject_count", source.subject_count),
        ("item_count", source.item_count),
    ] {
        output.push_str("- ")?;
        write_markdown_code_span(output, name)?;
        output.push_str(": ")?;
        write_markdown_code_span(output, &value.to_string())?;
        output.push_char('\n')?;
    }
    for (name, value) in &source.optional_audits {
        output.push_str("- Optional audit ")?;
        write_markdown_code_span(output, name)?;
        output.push_str(": ")?;
        if name == "wordpress_review" {
            write_markdown_code_span(output, &display_serializable(value)?)?;
            output.push_str(" (validated snapshot; semantic differences are shown below)")?;
        } else {
            write_markdown_code_span(output, &display_serializable(value)?)?;
        }
        output.push_char('\n')?;
    }
    output.push_char('\n')?;
    Ok(())
}

fn write_secret_exposure_comparison_markdown(
    output: &mut RenderBuffer,
    comparison: &SecretExposureComparison,
) -> Result<(), ComparisonError> {
    output.push_str("## Passive secret-exposure differences\n\n- Schema: ")?;
    write_markdown_code_span(output, comparison.schema)?;
    output.push_str("\n- Status: ")?;
    write_markdown_code_span(output, comparison.status)?;
    if let Some(reason) = comparison.reason {
        output.push_str("\n- Reason: ")?;
        write_markdown_code_span(output, reason)?;
    }
    output.push_str(
        "\n\nThis section compares validated, value-free audit projections. It does not validate a secret, authenticate a source, contact a provider, or establish remediation.\n\n",
    )?;
    for (label, facet) in [
        ("Methodology", &comparison.methodology),
        ("Coverage", &comparison.coverage),
    ] {
        output.push_fmt(format_args!("### Secret exposure {label}\n\n- Status: "))?;
        write_markdown_code_span(output, &facet.status)?;
        if !facet.changed_fields.is_empty() {
            output.push_str("\n- Changed fields: ")?;
            write_markdown_code_span(output, &facet.changed_fields.join(", "))?;
        }
        output.push_str("\n- Before: ")?;
        write_markdown_code_span(output, &display_json(facet.before.as_ref())?)?;
        output.push_str("\n- After: ")?;
        write_markdown_code_span(output, &display_json(facet.after.as_ref())?)?;
        output.push_str("\n- Interpretation: ")?;
        write_markdown_code_span(output, facet.note)?;
        output.push_str("\n\n")?;
    }
    output.push_str("### Secret exposure interpretation limits\n\n")?;
    for limit in comparison.interpretation_limits {
        output.push_str("- ")?;
        write_markdown_code_span(output, limit)?;
        output.push_char('\n')?;
    }
    output.push_char('\n')?;
    Ok(())
}

fn write_tls_observation_comparison_markdown(
    output: &mut RenderBuffer,
    comparison: &TlsObservationComparison,
) -> Result<(), ComparisonError> {
    output.push_str("## Existing-connection TLS observation differences\n\n- Schema: ")?;
    write_markdown_code_span(output, comparison.schema)?;
    output.push_str("\n- Status: ")?;
    write_markdown_code_span(output, comparison.status)?;
    if let Some(reason) = comparison.reason {
        output.push_str("\n- Reason: ")?;
        write_markdown_code_span(output, reason)?;
    }
    output.push_str(
        "\n\nThis section compares validated passive TLS audit projections. It does not enumerate server TLS support, authenticate a source, check revocation, or establish vulnerability or remediation.\n\n",
    )?;
    for (label, facet) in [
        ("Methodology", &comparison.methodology),
        ("Coverage", &comparison.coverage),
        (
            "Certificate observations",
            &comparison.certificate_observations,
        ),
    ] {
        output.push_fmt(format_args!("### TLS {label}\n\n- Status: "))?;
        write_markdown_code_span(output, &facet.status)?;
        if !facet.changed_fields.is_empty() {
            output.push_str("\n- Changed fields: ")?;
            write_markdown_code_span(output, &facet.changed_fields.join(", "))?;
        }
        output.push_str("\n- Before: ")?;
        write_markdown_code_span(output, &display_json(facet.before.as_ref())?)?;
        output.push_str("\n- After: ")?;
        write_markdown_code_span(output, &display_json(facet.after.as_ref())?)?;
        output.push_str("\n- Interpretation: ")?;
        write_markdown_code_span(output, facet.note)?;
        output.push_str("\n\n")?;
    }
    output.push_str("### TLS observation interpretation limits\n\n")?;
    for limit in comparison.interpretation_limits {
        output.push_str("- ")?;
        write_markdown_code_span(output, limit)?;
        output.push_char('\n')?;
    }
    output.push_char('\n')?;
    Ok(())
}

fn write_jwt_policy_review_comparison_markdown(
    output: &mut RenderBuffer,
    comparison: &JwtPolicyReviewComparison,
) -> Result<(), ComparisonError> {
    if comparison.target_selected {
        output.push_str("## JWT policy review differences\n\n- Schema: ")?;
    } else {
        output.push_str("## Local JWT policy review differences\n\n- Schema: ")?;
    }
    write_markdown_code_span(output, comparison.schema)?;
    output.push_str("\n- Status: ")?;
    write_markdown_code_span(output, comparison.status)?;
    if let Some(reason) = comparison.reason {
        output.push_str("\n- Reason: ")?;
        write_markdown_code_span(output, reason)?;
    }
    if comparison.target_selected {
        output.push_str(
            "\n\nThis section compares validated, value-free local policy projections and bounded target-control projections. It retains no token, claim, signature, key, selected marker name, or raw resource URL and does not establish a general authentication bypass, authorization effect, vulnerability, impact, or remediation.\n\n",
        )?;
    } else {
        output.push_str(
            "\n\nThis section compares validated, value-free local JWT audit projections. It does not expose the token, claims, signature, or key; contact a target; or establish target acceptance, authorization, vulnerability, or remediation.\n\n",
        )?;
    }
    for (label, facet) in [
        ("Methodology", &comparison.methodology),
        ("Coverage", &comparison.coverage),
        ("Outcome", &comparison.outcome),
    ] {
        output.push_fmt(format_args!("### JWT {label}\n\n- Status: "))?;
        write_markdown_code_span(output, &facet.status)?;
        if !facet.changed_fields.is_empty() {
            output.push_str("\n- Changed fields: ")?;
            write_markdown_code_span(output, &facet.changed_fields.join(", "))?;
        }
        output.push_str("\n- Before: ")?;
        write_markdown_code_span(output, &display_json(facet.before.as_ref())?)?;
        output.push_str("\n- After: ")?;
        write_markdown_code_span(output, &display_json(facet.after.as_ref())?)?;
        output.push_str("\n- Interpretation: ")?;
        write_markdown_code_span(output, facet.note)?;
        output.push_str("\n\n")?;
    }
    output.push_str("### JWT policy review interpretation limits\n\n")?;
    for limit in comparison.interpretation_limits {
        output.push_str("- ")?;
        write_markdown_code_span(output, limit)?;
        output.push_char('\n')?;
    }
    output.push_char('\n')?;
    Ok(())
}

fn write_control_reference_mapping_comparison_markdown(
    output: &mut RenderBuffer,
    comparison: &ControlReferenceMappingComparison,
) -> Result<(), ComparisonError> {
    output.push_str("## Control-reference mapping differences\n\n- Schema: ")?;
    write_markdown_code_span(output, comparison.schema)?;
    output.push_str("\n- Status: ")?;
    write_markdown_code_span(output, comparison.status)?;
    if let Some(reason) = comparison.reason {
        output.push_str("\n- Reason: ")?;
        write_markdown_code_span(output, reason)?;
    }
    output.push_str(
        "\n\nThis section compares a validated offline reference projection over already composed items. Catalogue, source, coverage, and relationship changes are methodology/reference-set differences, not target changes, remediation, compliance, certification, or legal conclusions.\n\n",
    )?;
    for (label, facet) in [
        ("Methodology", &comparison.methodology),
        ("Coverage", &comparison.coverage),
        ("Reference set", &comparison.reference_set),
    ] {
        output.push_fmt(format_args!("### Control-reference {label}\n\n- Status: "))?;
        write_markdown_code_span(output, &facet.status)?;
        if !facet.changed_fields.is_empty() {
            output.push_str("\n- Changed fields: ")?;
            write_markdown_code_span(output, &facet.changed_fields.join(", "))?;
        }
        output.push_str("\n- Before: ")?;
        write_markdown_code_span(output, &display_json(facet.before.as_ref())?)?;
        output.push_str("\n- After: ")?;
        write_markdown_code_span(output, &display_json(facet.after.as_ref())?)?;
        output.push_str("\n- Interpretation: ")?;
        write_markdown_code_span(output, facet.note)?;
        output.push_str("\n\n")?;
    }
    output.push_str("### Control-reference mapping interpretation limits\n\n")?;
    for limit in comparison.interpretation_limits {
        output.push_str("- ")?;
        write_markdown_code_span(output, limit)?;
        output.push_char('\n')?;
    }
    output.push_char('\n')?;
    Ok(())
}

fn write_recon_snapshot_import_comparison_markdown(
    output: &mut RenderBuffer,
    comparison: &ReconSnapshotImportComparison,
) -> Result<(), ComparisonError> {
    output.push_str("## Reconnaissance snapshot import differences\n\n- Schema: ")?;
    write_markdown_code_span(output, comparison.schema)?;
    output.push_str("\n- Status: ")?;
    write_markdown_code_span(output, comparison.status)?;
    if let Some(reason) = comparison.reason {
        output.push_str("\n- Reason: ")?;
        write_markdown_code_span(output, reason)?;
    }
    output.push_str("\n\nThis section compares validated inert local snapshot projections. Source, coverage, and hypothesis changes are imported-context differences, not target changes, findings, authorization, vulnerability, or remediation.\n\n")?;
    for (label, facet) in [
        ("Methodology", &comparison.methodology),
        ("Provenance and sources", &comparison.provenance_and_sources),
        (
            "Coverage and accounting",
            &comparison.coverage_and_accounting,
        ),
        ("Hypotheses", &comparison.hypotheses),
    ] {
        output.push_fmt(format_args!("### Recon snapshot {label}\n\n- Status: "))?;
        write_markdown_code_span(output, &facet.status)?;
        if !facet.changed_fields.is_empty() {
            output.push_str("\n- Changed fields: ")?;
            write_markdown_code_span(output, &facet.changed_fields.join(", "))?;
        }
        output.push_str("\n- Before: ")?;
        write_markdown_code_span(output, &display_json(facet.before.as_ref())?)?;
        output.push_str("\n- After: ")?;
        write_markdown_code_span(output, &display_json(facet.after.as_ref())?)?;
        output.push_str("\n- Interpretation: ")?;
        write_markdown_code_span(output, facet.note)?;
        output.push_str("\n\n")?;
    }
    output.push_str("### Reconnaissance snapshot interpretation limits\n\n")?;
    for limit in comparison.interpretation_limits {
        output.push_str("- ")?;
        write_markdown_code_span(output, limit)?;
        output.push_char('\n')?;
    }
    output.push_char('\n')?;
    Ok(())
}

fn write_recon_certspotter_comparison_markdown(
    output: &mut RenderBuffer,
    comparison: &ReconCertSpotterComparison,
) -> Result<(), ComparisonError> {
    output.push_str("## Cert Spotter provider differences\n\n- Schema: ")?;
    write_markdown_code_span(output, comparison.schema)?;
    output.push_str("\n- Status: ")?;
    write_markdown_code_span(output, comparison.status)?;
    if let Some(reason) = comparison.reason {
        output.push_str("\n- Reason: ")?;
        write_markdown_code_span(output, reason)?;
    }
    output.push_str("\n\nThis section compares validated bounded provider projections. Provider, methodology, coverage, and source-qualified hypothesis changes are saved-report context differences, not findings, scan authority, source authentication, ownership, currentness, vulnerability, or remediation.\n\n")?;
    for (label, facet) in [
        ("Provider", &comparison.provider),
        ("Methodology", &comparison.methodology),
        ("Coverage", &comparison.coverage),
        ("Source-qualified hypotheses", &comparison.hypotheses),
    ] {
        output.push_fmt(format_args!("### Cert Spotter {label}\n\n- Status: "))?;
        write_markdown_code_span(output, &facet.status)?;
        if !facet.changed_fields.is_empty() {
            output.push_str("\n- Changed fields: ")?;
            write_markdown_code_span(output, &facet.changed_fields.join(", "))?;
        }
        output.push_str("\n- Before: ")?;
        write_markdown_code_span(output, &display_json(facet.before.as_ref())?)?;
        output.push_str("\n- After: ")?;
        write_markdown_code_span(output, &display_json(facet.after.as_ref())?)?;
        output.push_str("\n- Interpretation: ")?;
        write_markdown_code_span(output, facet.note)?;
        output.push_str("\n\n")?;
    }
    output.push_str("### Cert Spotter interpretation limits\n\n")?;
    for limit in comparison.interpretation_limits {
        output.push_str("- ")?;
        write_markdown_code_span(output, limit)?;
        output.push_char('\n')?;
    }
    output.push_char('\n')?;
    Ok(())
}

fn write_wordpress_comparison_markdown(
    output: &mut RenderBuffer,
    comparison: &WordPressReviewComparison,
) -> Result<(), ComparisonError> {
    output.push_str("## WordPress review differences\n\n")?;
    output.push_str("- Schema: ")?;
    write_markdown_code_span(output, comparison.schema)?;
    output.push_str("\n- Status: ")?;
    write_markdown_code_span(output, comparison.status)?;
    if let Some(reason) = comparison.reason {
        output.push_str("\n- Reason: ")?;
        write_markdown_code_span(output, reason)?;
    }
    output.push_str("\n- Scope assurance: ")?;
    write_markdown_code_span(output, comparison.scope_assurance)?;
    output.push_str(
        "\n\nThis section compares validated display-only WordPress audit projections. It does not rerun the scan or establish remediation, newness, or causation.\n\n",
    )?;
    for (label, facet) in [
        ("Declared coverage", &comparison.coverage),
        ("Methodology", &comparison.methodology),
        ("Provenance", &comparison.provenance),
    ] {
        output.push_fmt(format_args!("### {label}\n\n- Status: "))?;
        write_markdown_code_span(output, &facet.status)?;
        if !facet.changed_fields.is_empty() {
            output.push_str("\n- Changed fields: ")?;
            write_markdown_code_span(output, &facet.changed_fields.join(", "))?;
        }
        output.push_str("\n- Before: ")?;
        write_markdown_code_span(output, &display_json(facet.before.as_ref())?)?;
        output.push_str("\n- After: ")?;
        write_markdown_code_span(output, &display_json(facet.after.as_ref())?)?;
        output.push_str("\n- Interpretation: ")?;
        write_markdown_code_span(output, facet.note)?;
        output.push_str("\n\n")?;
    }
    if let Some(facet) = &comparison.discovery_source_content {
        output.push_str("### Discovery source content\n\n- Status: ")?;
        write_markdown_code_span(output, &facet.status)?;
        if !facet.changed_fields.is_empty() {
            output.push_str("\n- Changed fields: ")?;
            write_markdown_code_span(output, &facet.changed_fields.join(", "))?;
        }
        output.push_str("\n- Before: ")?;
        write_markdown_code_span(output, &display_json(facet.before.as_ref())?)?;
        output.push_str("\n- After: ")?;
        write_markdown_code_span(output, &display_json(facet.after.as_ref())?)?;
        output.push_str("\n- Interpretation: ")?;
        write_markdown_code_span(output, facet.note)?;
        output.push_str("\n\n")?;
    }
    if let Some(fingerprints) = &comparison.asset_fingerprints {
        output.push_str("### Asset fingerprint candidates\n\n- Status: ")?;
        write_markdown_code_span(output, fingerprints.status)?;
        if let Some(reason) = fingerprints.reason {
            output.push_str("\n- Reason: ")?;
            write_markdown_code_span(output, reason)?;
        }
        output.push_str("\n\n")?;
        for (label, facet) in [
            ("Fingerprint methodology", &fingerprints.methodology),
            ("Finite reference catalogue", &fingerprints.catalogue),
            ("Resource coverage", &fingerprints.coverage),
        ] {
            output.push_fmt(format_args!("#### {label}\n\n- Status: "))?;
            write_markdown_code_span(output, &facet.status)?;
            if !facet.changed_fields.is_empty() {
                output.push_str("\n- Changed fields: ")?;
                write_markdown_code_span(output, &facet.changed_fields.join(", "))?;
            }
            output.push_str("\n- Before: ")?;
            write_markdown_code_span(output, &display_json(facet.before.as_ref())?)?;
            output.push_str("\n- After: ")?;
            write_markdown_code_span(output, &display_json(facet.after.as_ref())?)?;
            output.push_str("\n- Interpretation: ")?;
            write_markdown_code_span(output, facet.note)?;
            output.push_str("\n\n")?;
        }
        write_wordpress_entity_changes_markdown(
            output,
            "Fingerprint resources",
            &fingerprints.resources,
        )?;
        write_wordpress_entity_changes_markdown(
            output,
            "Fingerprint candidate sets",
            &fingerprints.components,
        )?;
        output.push_str("#### Fingerprint interpretation limits\n\n")?;
        for limit in fingerprints.interpretation_limits {
            output.push_str("- ")?;
            write_markdown_code_span(output, limit)?;
            output.push_char('\n')?;
        }
        output.push_char('\n')?;
    }
    write_wordpress_entity_changes_markdown(output, "Components", &comparison.components)?;
    write_wordpress_entity_changes_markdown(output, "Advisories", &comparison.advisories)?;
    output.push_str("### Interpretation limits\n\n")?;
    for limit in comparison.interpretation_limits {
        output.push_str("- ")?;
        write_markdown_code_span(output, limit)?;
        output.push_char('\n')?;
    }
    output.push_char('\n')?;
    Ok(())
}

fn write_wordpress_entity_changes_markdown<K: Serialize>(
    output: &mut RenderBuffer,
    label: &str,
    changes: &WordPressEntityChanges<K>,
) -> Result<(), ComparisonError> {
    output.push_fmt(format_args!("### {label}\n\n"))?;
    output.push_fmt(format_args!(
        "- Paired unchanged: {}\n- Paired changed: {}\n- Only in supplied before audit: {}\n- Only in supplied after audit: {}\n\n",
        changes.paired_unchanged_count,
        changes.paired_changed.len(),
        changes.only_in_before.len(),
        changes.only_in_after.len(),
    ))?;
    for change in &changes.paired_changed {
        output.push_str("#### Paired identity with changed content\n\n- Key: ")?;
        write_markdown_code_span(output, &display_serializable(&change.key)?)?;
        output.push_str("\n- Changed dimensions: ")?;
        write_markdown_code_span(output, &change.changed_dimensions.join(", "))?;
        output.push_str("\n- Before: ")?;
        write_markdown_code_span(output, &display_serializable(&change.before)?)?;
        output.push_str("\n- After: ")?;
        write_markdown_code_span(output, &display_serializable(&change.after)?)?;
        output.push_str("\n\n")?;
    }
    for (side, entities) in [
        ("before", &changes.only_in_before),
        ("after", &changes.only_in_after),
    ] {
        for entity in entities {
            output.push_fmt(format_args!(
                "#### Present only in the supplied {side} audit\n\n- Key: "
            ))?;
            write_markdown_code_span(output, &display_serializable(&entity.key)?)?;
            output.push_str("\n- Content: ")?;
            write_markdown_code_span(output, &display_serializable(&entity.content)?)?;
            output.push_str("\n- Interpretation: ")?;
            write_markdown_code_span(output, entity.interpretation)?;
            output.push_str("\n\n")?;
        }
    }
    Ok(())
}

fn display_json(value: Option<&Value>) -> Result<String, ComparisonError> {
    value.map_or_else(
        || Ok("not recorded".to_owned()),
        |value| serde_json::to_string(value).map_err(|_| ComparisonError::Serialization),
    )
}

fn display_serializable(value: &impl Serialize) -> Result<String, ComparisonError> {
    serde_json::to_string(value).map_err(|_| ComparisonError::Serialization)
}

fn write_projection(
    output: &mut RenderBuffer,
    projection: &impl Serialize,
) -> Result<(), ComparisonError> {
    let value = serde_json::to_value(projection).map_err(|_| ComparisonError::Serialization)?;
    let fields = value.as_object().ok_or(ComparisonError::Serialization)?;
    for (field, value) in fields {
        output.push_str("- ")?;
        write_markdown_code_span(output, field)?;
        output.push_str(": ")?;
        let text = match value {
            Value::String(text) => text.clone(),
            _ => value.to_string(),
        };
        write_markdown_code_span(output, &text)?;
        output.push_char('\n')?;
    }
    output.push_char('\n')?;
    Ok(())
}
