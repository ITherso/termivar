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
/// Additive, display-only WordPress comparison section carried by comparison v1.
pub(super) const WORDPRESS_COMPARISON_SCHEMA: &str = "termivar-wordpress-review-comparison/v1";
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
    pub(super) wordpress_review_comparison: Option<WordPressReviewComparison>,
    pub(super) only_in_after: Vec<ComparisonItem>,
    pub(super) only_in_before: Vec<ComparisonItem>,
    pub(super) changed: Vec<ComparisonItem>,
    pub(super) unchanged: Vec<ComparisonItem>,
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
    pub(super) components: WordPressEntityChanges<WordPressComponentKey>,
    pub(super) advisories: WordPressEntityChanges<WordPressAdvisoryKey>,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ImportedWordPressAudit {
    pub(super) coverage: Value,
    pub(super) inventory_coverage_recorded: bool,
    pub(super) methodology: Value,
    pub(super) provenance: Value,
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
    wordpress_review: Option<ImportedWordPressAudit>,
}

struct ImportedItem {
    capability_id: String,
    projection: ItemProjection,
}

fn compare_documents(
    before: ImportedDocument,
    mut after: ImportedDocument,
) -> Result<ComparisonDocument, ComparisonError> {
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
        wordpress_review_comparison,
        only_in_after: Vec::new(),
        only_in_before: Vec::new(),
        changed: Vec::new(),
        unchanged: Vec::new(),
    };
    for (fingerprint, old) in before.items {
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
        } else {
            document.only_in_before.push(ComparisonItem {
                fingerprint,
                capability_id: old.capability_id,
                before: Some(old.projection),
                after: None,
                changed_fields: Vec::new(),
            });
        }
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

fn compare_wordpress_reviews(
    before: Option<&ImportedWordPressAudit>,
    after: Option<&ImportedWordPressAudit>,
) -> Option<WordPressReviewComparison> {
    if before.is_none() && after.is_none() {
        return None;
    }
    let status = if before.is_some() && after.is_some() {
        "compared"
    } else {
        "not_compared"
    };
    let reason = match (before, after) {
        (None, Some(_)) => Some("before_audit_missing"),
        (Some(_), None) => Some("after_audit_missing"),
        _ => None,
    };
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
    let (components, advisories) = if let (Some(before), Some(after)) = (before, after) {
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
        schema: WORDPRESS_COMPARISON_SCHEMA,
        status,
        reason,
        scope_assurance: "operator-declared",
        coverage,
        methodology,
        provenance,
        components,
        advisories,
        interpretation_limits: [
            "WordPress differences compare validated display-only audit projections; they do not rerun an assessment.",
            "One-sided components or advisories do not establish installation, removal, discovery time, or remediation.",
            "Simultaneous inventory, source, methodology, and applicability changes are listed without assigning cause.",
            "Applicability remains an imported declared-data result, not proof of exploitability or safety.",
            "A missing audit or reduced declaration changes coverage; it does not mean all WordPress issues disappeared.",
        ],
    })
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
