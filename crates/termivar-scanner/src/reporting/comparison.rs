//! Offline, display-only comparison of untrusted rendered assessment documents.
//!
//! Importing a document does not authenticate its origin, establish equal scan
//! coverage, or mint runtime evidence, findings, verification, or target authority.
//! Report-local reference numbers are validated but never used as stable identity.

use std::{collections::BTreeMap, error::Error, fmt};

use serde::Serialize;
use serde_json::Value;

use super::{render_serializable_json, write_markdown_code_span, RenderBuffer, ReportError};

mod html;
mod import;
#[cfg(test)]
mod tests;

/// Versioned display-only comparison document schema.
pub const COMPARISON_DOCUMENT_SCHEMA: &str = "termivar-report-comparison/v1";
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

#[derive(Debug, Serialize)]
pub(super) struct ComparisonDocument {
    pub(super) schema: &'static str,
    pub(super) scope_assurance: &'static str,
    pub(super) coverage_equivalence: &'static str,
    pub(super) source_authenticity: &'static str,
    pub(super) interpretation_limits: [&'static str; 4],
    pub(super) before: SourceMetadata,
    pub(super) after: SourceMetadata,
    pub(super) only_in_after: Vec<ComparisonItem>,
    pub(super) only_in_before: Vec<ComparisonItem>,
    pub(super) changed: Vec<ComparisonItem>,
    pub(super) unchanged: Vec<ComparisonItem>,
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
}

struct ImportedItem {
    capability_id: String,
    projection: ItemProjection,
}

fn compare_documents(
    before: ImportedDocument,
    mut after: ImportedDocument,
) -> Result<ComparisonDocument, ComparisonError> {
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
        write_projection(&mut output, source)?;
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
