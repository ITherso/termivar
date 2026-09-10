//! Deterministic, bounded rendering for validated [`termivar_core::RunReport`] values.

pub mod comparison;

#[cfg(all(feature = "scanning", feature = "rest-review"))]
use crate::rest_review::RestDocumentedResponseClass;
#[cfg(feature = "scanning")]
use crate::web_runtime::{
    AssessmentBasis, AssessmentRunReport, AssessmentRunReportError, ScanProfileV1,
    WebAssessmentRunReport,
};
#[cfg(all(feature = "scanning", feature = "openapi-review"))]
use crate::web_runtime::{OpenApiRuntimeOutcome, OPENAPI_REVIEW_CAPABILITY_ID};
#[cfg(all(feature = "scanning", feature = "rest-review"))]
use crate::web_runtime::{
    RestObservedMediaClass, RestRuntimeOutcome, MAX_REST_REVIEW_ACTIVE_VERIFICATIONS,
    MAX_REST_REVIEW_REQUESTS, REST_REVIEW_CAPABILITY_ID,
};
#[cfg(all(feature = "scanning", feature = "authorization-review"))]
use crate::{
    authorization_review::{
        AuthorizationReviewOutcome, HARD_MAX_AUTHORIZATION_REVIEW_IGNORED_PATHS,
        HARD_MAX_AUTHORIZATION_REVIEW_SELECTED_PATHS,
    },
    web_runtime::{MAX_AUTHORIZATION_REVIEW_REQUESTS, RESOURCE_AUTHORIZATION_REVIEW_CAPABILITY_ID},
};
#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
use crate::{
    web_runtime::{
        WebAssessmentWordPressAudit, WORDPRESS_DISCOVERY_OBSERVATION_CAPABILITY_ID,
        WORDPRESS_REVIEW_CAPABILITY_ID,
    },
    wordpress_review::{
        WordPressActivationState, WordPressAdvisoryCatalogSchema, WordPressApplicability,
        WordPressCatalogStatus, WordPressComparisonProfile, WordPressComponentEvidenceClass,
        WordPressComponentKind, WordPressEvidenceConfidence, WordPressEvidenceSource,
        WordPressExecutionStatus, WordPressExternalApplicability,
        WordPressExternalComparisonPolicy, WordPressExternalRangeReason,
        WordPressExternalRangeRelation, WordPressExternalVersionEvidenceStatus,
        WordPressExternalVersionRelation, WordPressExternalVersionRelationReason,
        WordPressHostingOs, WordPressInventoryCategoryStatus, WordPressInventoryEntryStatus,
        WordPressInventoryLimitationReason, WordPressLocalInputClass, WordPressMultisiteState,
        WordPressPatchState, WordPressPrerequisite, WordPressPrerequisiteOutcome,
        WordPressVersionRelation, WordPressVersionResolution, WordPressVersionResolutionReason,
        WordfenceV3CvssRating, WordfenceV3IdentityMapping, WordfenceV3RangeValue,
        MAX_WORDFENCE_V3_SOFTWARE_PER_RECORD, MAX_WORDPRESS_ADVISORY_RECORDS,
        MAX_WORDPRESS_EXTERNAL_IDENTITY_LIMITATION_PROJECTIONS, MAX_WORDPRESS_RESULT_COMPONENTS,
        MAX_WORDPRESS_RESULT_VERSION_EVIDENCE, MAX_WORDPRESS_SAVED_INVENTORY_BYTES,
        MAX_WORDPRESS_SIGNALS, WORDFENCE_V3_IDENTITY_MAPPING_POLICY, WORDFENCE_V3_MAPPING_REVISION,
        WORDFENCE_V3_MAPPING_REVISION_V2, WORDFENCE_V3_RESOURCE_POLICY_V1,
        WORDFENCE_V3_RESOURCE_POLICY_V2, WORDFENCE_V3_RESOURCE_POLICY_V3,
        WORDPRESS_ADVISORY_CATALOG_SCHEMA, WORDPRESS_ADVISORY_CATALOG_SCHEMA_V2,
    },
};
use serde::Serialize;
use std::{error::Error, fmt, io};
use termivar_core::{
    OutcomeStatus, ResourceAccounting, ResourceAccountingMode, RunOutcomeRecord, RunReport,
    RunStatus, RunStepStatus, RunStopCode, SecuritySeverity,
};

/// Stable schema name for rendered run documents.
pub const REPORT_DOCUMENT_SCHEMA: &str = "venom-rendered-run/v1";
/// Stable schema name for the additive, redacted assessment document.
#[cfg(feature = "scanning")]
pub const ASSESSMENT_REPORT_DOCUMENT_SCHEMA: &str = "venom-rendered-assessment/v1";
/// Maximum UTF-8 bytes returned by one render operation.
pub const MAX_RENDERED_REPORT_BYTES: usize = 16 * 1_024 * 1_024;

const REPORT_FORMATS: [ReportFormat; 4] = [
    ReportFormat::Json,
    ReportFormat::Csv,
    ReportFormat::Html,
    ReportFormat::Markdown,
];

/// Supported deterministic report encodings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ReportFormat {
    /// Compact UTF-8 JSON.
    Json,
    /// UTF-8 comma-separated records.
    Csv,
    /// Self-contained UTF-8 HTML.
    Html,
    /// UTF-8 Markdown.
    Markdown,
}

impl ReportFormat {
    /// Returns the stable format token.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Csv => "csv",
            Self::Html => "html",
            Self::Markdown => "markdown",
        }
    }

    /// Returns the stable media type.
    pub const fn media_type(self) -> &'static str {
        match self {
            Self::Json => "application/json",
            Self::Csv => "text/csv; charset=utf-8",
            Self::Html => "text/html; charset=utf-8",
            Self::Markdown => "text/markdown; charset=utf-8",
        }
    }

    /// Returns the conventional extension without a leading period.
    pub const fn extension(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Csv => "csv",
            Self::Html => "html",
            Self::Markdown => "md",
        }
    }
}

/// Fail-closed rendering errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReportError {
    /// Escaped output would exceed the public byte ceiling.
    OutputLimitExceeded {
        /// Configured maximum returned size.
        limit: usize,
    },
    /// A deterministic projection could not be serialized.
    Serialization,
}

impl fmt::Display for ReportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutputLimitExceeded { .. } => {
                formatter.write_str("rendered report exceeds the output byte limit")
            },
            Self::Serialization => formatter.write_str("rendered report serialization failed"),
        }
    }
}

impl Error for ReportError {}

/// Stateless renderer for supported encodings.
#[derive(Debug, Default, Clone, Copy)]
pub struct ReportGenerator;

impl ReportGenerator {
    /// Renders one report, returning no partial document on failure.
    pub fn generate(report: &RunReport, format: ReportFormat) -> Result<String, ReportError> {
        let document = ReportDocument::from_report(report)?;
        render_with_limit(&document, format, MAX_RENDERED_REPORT_BYTES)
    }

    /// Consumes one completed runtime-owned web assessment into its typed
    /// product envelope. The generic run envelope is minted internally from
    /// the runtime's clock and metered accounting; callers cannot supply or
    /// replace it.
    #[cfg(feature = "scanning")]
    pub fn compose_assessment(
        report: WebAssessmentRunReport,
        profile: ScanProfileV1,
    ) -> Result<AssessmentRunReport, AssessmentRunReportError> {
        report.into_assessment_report(profile)
    }

    /// Renders one completed typed assessment through the existing bounded,
    /// context-safe report encoders. This is an additive document surface and
    /// never changes the [`REPORT_DOCUMENT_SCHEMA`] compatibility contract.
    #[cfg(feature = "scanning")]
    pub fn generate_assessment(
        report: &AssessmentRunReport,
        format: ReportFormat,
    ) -> Result<String, ReportError> {
        let document = AssessmentDocument::from_report(report)?;
        render_assessment_with_limit(&document, format, MAX_RENDERED_REPORT_BYTES)
    }

    /// Returns all formats in stable negotiation order.
    pub const fn available_formats() -> &'static [ReportFormat] {
        &REPORT_FORMATS
    }
}

fn render_with_limit(
    document: &ReportDocument<'_>,
    format: ReportFormat,
    limit: usize,
) -> Result<String, ReportError> {
    match format {
        ReportFormat::Json => render_json(document, limit),
        ReportFormat::Csv => render_csv(document, limit),
        ReportFormat::Html => render_html(document, limit),
        ReportFormat::Markdown => render_markdown(document, limit),
    }
}

fn render_json(document: &ReportDocument<'_>, limit: usize) -> Result<String, ReportError> {
    render_serializable_json(document, limit)
}

fn render_serializable_json(
    document: &impl Serialize,
    limit: usize,
) -> Result<String, ReportError> {
    let mut raw = RawJsonWriter::new(limit);
    if serde_json::to_writer(&mut raw, document).is_err() {
        return if raw.exceeded {
            Err(ReportError::OutputLimitExceeded { limit })
        } else {
            Err(ReportError::Serialization)
        };
    }
    let raw = std::str::from_utf8(&raw.bytes).map_err(|_| ReportError::Serialization)?;
    let mut output = RenderBuffer::new(limit);
    for character in raw.chars() {
        if character.is_control() || is_bidi_control(character) {
            write_json_codepoint(&mut output, character)?;
        } else {
            output.push_char(character)?;
        }
    }
    Ok(output.finish())
}

struct RawJsonWriter {
    bytes: Vec<u8>,
    limit: usize,
    exceeded: bool,
}

impl RawJsonWriter {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
            exceeded: false,
        }
    }
}

impl io::Write for RawJsonWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Some(next_len) = self.bytes.len().checked_add(bytes.len()) else {
            self.exceeded = true;
            return Err(io::Error::other("raw JSON limit reached"));
        };
        if next_len > self.limit {
            self.exceeded = true;
            return Err(io::Error::other("raw JSON limit reached"));
        }
        self.bytes
            .try_reserve(bytes.len())
            .map_err(|_| io::Error::other("raw JSON allocation failed"))?;
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn write_json_codepoint(output: &mut RenderBuffer, character: char) -> Result<(), ReportError> {
    let codepoint = u32::from(character);
    if codepoint <= u32::from(u16::MAX) {
        return output.push_fmt(format_args!("\\u{codepoint:04X}"));
    }
    let supplementary = codepoint - 0x1_0000;
    let high = 0xD800 + (supplementary >> 10);
    let low = 0xDC00 + (supplementary & 0x3FF);
    output.push_fmt(format_args!("\\u{high:04X}\\u{low:04X}"))
}

struct RenderBuffer {
    value: String,
    limit: usize,
}

impl RenderBuffer {
    fn new(limit: usize) -> Self {
        Self {
            value: String::new(),
            limit,
        }
    }

    fn push_str(&mut self, value: &str) -> Result<(), ReportError> {
        let Some(next_len) = self.value.len().checked_add(value.len()) else {
            return Err(ReportError::OutputLimitExceeded { limit: self.limit });
        };
        if next_len > self.limit {
            return Err(ReportError::OutputLimitExceeded { limit: self.limit });
        }
        self.value.push_str(value);
        Ok(())
    }

    fn push_char(&mut self, value: char) -> Result<(), ReportError> {
        let next_len = self
            .value
            .len()
            .checked_add(value.len_utf8())
            .ok_or(ReportError::OutputLimitExceeded { limit: self.limit })?;
        if next_len > self.limit {
            return Err(ReportError::OutputLimitExceeded { limit: self.limit });
        }
        self.value.push(value);
        Ok(())
    }

    fn push_fmt(&mut self, arguments: fmt::Arguments<'_>) -> Result<(), ReportError> {
        fmt::write(self, arguments)
            .map_err(|_| ReportError::OutputLimitExceeded { limit: self.limit })
    }

    fn finish(self) -> String {
        self.value
    }
}

impl fmt::Write for RenderBuffer {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        self.push_str(value).map_err(|_| fmt::Error)
    }

    fn write_char(&mut self, value: char) -> fmt::Result {
        self.push_char(value).map_err(|_| fmt::Error)
    }
}

const CSV_HEADERS: [&str; 14] = [
    "record_type",
    "name",
    "value",
    "status_or_disposition",
    "kind",
    "action_id",
    "severity",
    "confidence_ppm",
    "evidence_count",
    "limit",
    "consumed",
    "remaining",
    "duration_ms",
    "redacted_summary",
];

fn render_csv(document: &ReportDocument<'_>, limit: usize) -> Result<String, ReportError> {
    let mut output = RenderBuffer::new(limit);
    write_csv_row(&mut output, CSV_HEADERS)?;
    for (name, value) in [
        ("schema", document.schema),
        ("source_schema", document.source_schema),
        ("status", document.status),
        ("stop_code", document.stop_code),
        ("target", document.target),
        ("authorized_origin", document.authorized_origin),
        ("started_at", document.started_at.as_str()),
        ("completed_at", document.completed_at.as_str()),
    ] {
        write_csv_row(
            &mut output,
            [
                "document", name, value, "", "", "", "", "", "", "", "", "", "", "",
            ],
        )?;
    }
    for (name, dimension) in document.accounting.dimensions() {
        write_csv_row(
            &mut output,
            [
                "accounting",
                name,
                dimension.mode,
                "",
                "",
                "",
                "",
                "",
                "",
                dimension.limit.as_deref().unwrap_or(""),
                dimension.consumed.as_deref().unwrap_or(""),
                dimension.remaining.as_deref().unwrap_or(""),
                "",
                "",
            ],
        )?;
    }
    for step in &document.steps {
        let ordinal = step.ordinal.to_string();
        write_csv_row(
            &mut output,
            [
                "step",
                &ordinal,
                "",
                step.status,
                "",
                step.action_id,
                "",
                "",
                "",
                "",
                "",
                "",
                &step.duration_ms,
                "",
            ],
        )?;
    }
    for (index, outcome) in document.outcomes.iter().enumerate() {
        let index = (index + 1).to_string();
        let confidence_ppm = outcome.confidence_ppm.to_string();
        let evidence_count = outcome.evidence_count.to_string();
        write_csv_row(
            &mut output,
            [
                "outcome",
                &index,
                "",
                outcome.disposition,
                outcome.kind,
                outcome.action_id,
                outcome.severity,
                &confidence_ppm,
                &evidence_count,
                "",
                "",
                "",
                "",
                outcome.redacted_summary,
            ],
        )?;
    }
    Ok(output.finish())
}

fn write_csv_row(
    output: &mut RenderBuffer,
    cells: [&str; CSV_HEADERS.len()],
) -> Result<(), ReportError> {
    for (index, cell) in cells.into_iter().enumerate() {
        if index != 0 {
            output.push_char(',')?;
        }
        write_csv_cell(output, cell)?;
    }
    output.push_char('\n')
}

fn write_csv_cell(output: &mut RenderBuffer, value: &str) -> Result<(), ReportError> {
    output.push_char('"')?;
    if starts_csv_formula_after_whitespace(value) {
        output.push_char('\'')?;
    }
    for character in value.chars() {
        match character {
            '"' => output.push_str("\"\"")?,
            '\'' => output.push_str("\\u{0027}")?,
            '\\' => output.push_str("\\\\")?,
            character if character.is_control() || is_bidi_control(character) => {
                write_visible_codepoint(output, character)?;
            },
            character => output.push_char(character)?,
        }
    }
    output.push_char('"')
}

fn starts_csv_formula_after_whitespace(value: &str) -> bool {
    matches!(
        value.chars().find(|character| !character.is_whitespace()),
        Some('=' | '+' | '-' | '@')
    )
}

fn render_html(document: &ReportDocument<'_>, limit: usize) -> Result<String, ReportError> {
    let mut output = RenderBuffer::new(limit);
    output.push_str(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; base-uri 'none'; form-action 'none'\">\
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
<title>Termivar run report</title><style>\
:root{color-scheme:light dark}body{font:14px/1.5 system-ui,sans-serif;margin:2rem;max-width:90rem}\
h1,h2{line-height:1.2}.lifecycle{border:3px solid currentColor;padding:.8rem;font-size:1.1rem}.meta{display:grid;grid-template-columns:max-content 1fr;gap:.3rem 1rem}\
table{border-collapse:collapse;width:100%;margin-block:1rem 2rem}th,td{border:1px solid currentColor;padding:.35rem;text-align:left;vertical-align:top}\
code{overflow-wrap:anywhere}.empty{font-style:italic}</style></head><body><main>\
<h1>Termivar run report</h1>",
    )?;
    if document.status == "complete" {
        output
            .push_str("<p class=\"lifecycle\"><strong>Lifecycle status:</strong> completed.</p>")?;
    } else {
        output.push_str(
            "<aside class=\"lifecycle\"><strong>Lifecycle notice:</strong> Run did not complete. Status <code>",
        )?;
        write_html_text(&mut output, document.status)?;
        output.push_str("</code>; stop code <code>")?;
        write_html_text(&mut output, document.stop_code)?;
        output.push_str("</code>.</aside>")?;
    }
    output.push_str("<dl class=\"meta\">")?;
    for (label, value) in document.metadata() {
        output.push_str("<dt>")?;
        write_html_text(&mut output, label)?;
        output.push_str("</dt><dd><code>")?;
        write_html_text(&mut output, value)?;
        output.push_str("</code></dd>")?;
    }
    output.push_str(
        "</dl><section><h2>Resource accounting</h2><table><thead><tr>\
<th>Dimension</th><th>Mode</th><th>Limit</th><th>Consumed</th><th>Remaining</th>\
</tr></thead><tbody>",
    )?;
    for (name, dimension) in document.accounting.dimensions() {
        output.push_str("<tr><td><code>")?;
        write_html_text(&mut output, name)?;
        output.push_str("</code></td><td><code>")?;
        write_html_text(&mut output, dimension.mode)?;
        output.push_str("</code></td>")?;
        write_html_optional_decimal(&mut output, dimension.limit.as_deref())?;
        write_html_optional_decimal(&mut output, dimension.consumed.as_deref())?;
        write_html_optional_decimal(&mut output, dimension.remaining.as_deref())?;
        output.push_str("</tr>")?;
    }
    output.push_str("</tbody></table></section><section><h2>Steps</h2>")?;
    if document.steps.is_empty() {
        output.push_str("<p class=\"empty\">No step records.</p>")?;
    } else {
        output.push_str(
            "<table><thead><tr><th>Ordinal</th><th>Action</th><th>Status</th><th>Duration (ms)</th>\
</tr></thead><tbody>",
        )?;
        for step in &document.steps {
            output.push_fmt(format_args!("<tr><td>{}</td><td><code>", step.ordinal))?;
            write_html_text(&mut output, step.action_id)?;
            output.push_str("</code></td><td><code>")?;
            write_html_text(&mut output, step.status)?;
            output.push_fmt(format_args!(
                "</code></td><td>{}</td></tr>",
                step.duration_ms
            ))?;
        }
        output.push_str("</tbody></table>")?;
    }
    output.push_str("</section><section><h2>Outcomes</h2>")?;
    if document.outcomes.is_empty() {
        output.push_str("<p class=\"empty\">No outcome records.</p>")?;
    } else {
        output.push_str(
            "<table><thead><tr><th>Kind</th><th>Action</th><th>Severity</th>\
<th>Disposition</th><th>Confidence (ppm)</th><th>Evidence count</th><th>Redacted summary</th>\
</tr></thead><tbody>",
        )?;
        for outcome in &document.outcomes {
            output.push_str("<tr><td><code>")?;
            write_html_text(&mut output, outcome.kind)?;
            output.push_str("</code></td><td><code>")?;
            write_html_text(&mut output, outcome.action_id)?;
            output.push_str("</code></td><td><code>")?;
            write_html_text(&mut output, outcome.severity)?;
            output.push_str("</code></td><td><code>")?;
            write_html_text(&mut output, outcome.disposition)?;
            output.push_fmt(format_args!(
                "</code></td><td>{}</td><td>{}</td><td><code>",
                outcome.confidence_ppm, outcome.evidence_count
            ))?;
            write_html_text(&mut output, outcome.redacted_summary)?;
            output.push_str("</code></td></tr>")?;
        }
        output.push_str("</tbody></table>")?;
    }
    output.push_str("</section></main></body></html>")?;
    Ok(output.finish())
}

fn write_html_optional_decimal(
    output: &mut RenderBuffer,
    value: Option<&str>,
) -> Result<(), ReportError> {
    match value {
        Some(value) => {
            output.push_str("<td>")?;
            write_html_text(output, value)?;
            output.push_str("</td>")
        },
        None => output.push_str("<td><span class=\"empty\">not reported</span></td>"),
    }
}

fn write_html_text(output: &mut RenderBuffer, value: &str) -> Result<(), ReportError> {
    for character in value.chars() {
        match character {
            '&' => output.push_str("&amp;")?,
            '<' => output.push_str("&lt;")?,
            '>' => output.push_str("&gt;")?,
            '"' => output.push_str("&quot;")?,
            '\'' => output.push_str("&#39;")?,
            '\\' => output.push_str("\\\\")?,
            character if character.is_control() || is_bidi_control(character) => {
                write_visible_codepoint(output, character)?;
            },
            character => output.push_char(character)?,
        }
    }
    Ok(())
}

fn render_markdown(document: &ReportDocument<'_>, limit: usize) -> Result<String, ReportError> {
    let mut output = RenderBuffer::new(limit);
    output.push_str("# Termivar run report\n\n")?;
    if document.status != "complete" {
        output.push_str("> **Lifecycle notice:** This run did not complete. Status ")?;
        write_markdown_code_span(&mut output, document.status)?;
        output.push_str("; stop code ")?;
        write_markdown_code_span(&mut output, document.stop_code)?;
        output.push_str(".\n\n")?;
    }
    for (label, value) in document.metadata() {
        output.push_fmt(format_args!("- {label}: "))?;
        write_markdown_code_span(&mut output, value)?;
        output.push_char('\n')?;
    }

    output.push_str("\n## Resource accounting\n\n")?;
    for (name, dimension) in document.accounting.dimensions() {
        output.push_str("- Dimension ")?;
        write_markdown_code_span(&mut output, name)?;
        output.push_str(": mode ")?;
        write_markdown_code_span(&mut output, dimension.mode)?;
        output.push_str(", limit ")?;
        write_markdown_optional_decimal(&mut output, dimension.limit.as_deref())?;
        output.push_str(", consumed ")?;
        write_markdown_optional_decimal(&mut output, dimension.consumed.as_deref())?;
        output.push_str(", remaining ")?;
        write_markdown_optional_decimal(&mut output, dimension.remaining.as_deref())?;
        output.push_char('\n')?;
    }

    output.push_str("\n## Steps\n\n")?;
    if document.steps.is_empty() {
        output.push_str("No step records.\n")?;
    } else {
        for step in &document.steps {
            output.push_fmt(format_args!("### Step {}\n\n- Action: ", step.ordinal))?;
            write_markdown_code_span(&mut output, step.action_id)?;
            output.push_str("\n- Status: ")?;
            write_markdown_code_span(&mut output, step.status)?;
            output.push_fmt(format_args!("\n- Duration (ms): {}\n\n", step.duration_ms))?;
        }
    }

    output.push_str("## Outcomes\n\n")?;
    if document.outcomes.is_empty() {
        output.push_str("No outcome records.\n")?;
    } else {
        for (index, outcome) in document.outcomes.iter().enumerate() {
            output.push_fmt(format_args!("### Outcome {}\n\n- Kind: ", index + 1))?;
            write_markdown_code_span(&mut output, outcome.kind)?;
            output.push_str("\n- Action: ")?;
            write_markdown_code_span(&mut output, outcome.action_id)?;
            output.push_str("\n- Severity: ")?;
            write_markdown_code_span(&mut output, outcome.severity)?;
            output.push_str("\n- Disposition: ")?;
            write_markdown_code_span(&mut output, outcome.disposition)?;
            output.push_fmt(format_args!(
                "\n- Confidence (ppm): {}\n- Evidence count: {}\n- Redacted summary: ",
                outcome.confidence_ppm, outcome.evidence_count
            ))?;
            write_markdown_code_span(&mut output, outcome.redacted_summary)?;
            output.push_str("\n\n")?;
        }
    }
    Ok(output.finish())
}

fn write_markdown_optional_decimal(
    output: &mut RenderBuffer,
    value: Option<&str>,
) -> Result<(), ReportError> {
    match value {
        Some(value) => write_markdown_code_span(output, value),
        None => output.push_str("`not reported`"),
    }
}

fn write_markdown_code_span(output: &mut RenderBuffer, value: &str) -> Result<(), ReportError> {
    let visible = if value.is_empty() {
        String::from("\\u{EMPTY}")
    } else {
        visible_text(value)
    };
    let fence_length = longest_backtick_run(&visible) + 1;
    for _ in 0..fence_length {
        output.push_char('`')?;
    }
    let all_spaces = visible.chars().all(|character| character == ' ');
    let needs_padding = !all_spaces
        && (visible.starts_with('`')
            || visible.starts_with(' ')
            || visible.ends_with('`')
            || visible.ends_with(' '));
    if needs_padding {
        output.push_char(' ')?;
    }
    output.push_str(&visible)?;
    if needs_padding {
        output.push_char(' ')?;
    }
    for _ in 0..fence_length {
        output.push_char('`')?;
    }
    Ok(())
}

fn longest_backtick_run(value: &str) -> usize {
    let mut current = 0;
    let mut longest = 0;
    for character in value.chars() {
        if character == '`' {
            current += 1;
            longest = longest.max(current);
        } else {
            current = 0;
        }
    }
    longest
}

fn visible_text(value: &str) -> String {
    let mut visible = String::with_capacity(value.len());
    for character in value.chars() {
        if character == '\\' {
            visible.push_str("\\\\");
        } else if character.is_control() || is_bidi_control(character) {
            push_visible_codepoint(&mut visible, character);
        } else {
            visible.push(character);
        }
    }
    visible
}

fn push_visible_codepoint(output: &mut String, character: char) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let codepoint = u32::from(character);
    output.push_str("\\u{");
    for shift in [12, 8, 4, 0] {
        let index = ((codepoint >> shift) & 0xF) as usize;
        output.push(char::from(HEX[index]));
    }
    output.push('}');
}

#[cfg(feature = "scanning")]
fn render_assessment_with_limit(
    document: &AssessmentDocument<'_>,
    format: ReportFormat,
    limit: usize,
) -> Result<String, ReportError> {
    document.validate()?;
    match format {
        ReportFormat::Json => render_serializable_json(document, limit),
        ReportFormat::Csv => render_assessment_csv(document, limit),
        ReportFormat::Html => render_assessment_html(document, limit),
        ReportFormat::Markdown => render_assessment_markdown(document, limit),
    }
}

#[cfg(feature = "scanning")]
const ASSESSMENT_CSV_HEADERS: [&str; 30] = [
    "record_type",
    "document_schema",
    "source_schema",
    "run_schema",
    "profile_schema",
    "profile",
    "status",
    "subject_count",
    "item_count",
    "item_schema",
    "capability_id",
    "subject_reference",
    "title",
    "disposition",
    "claim_basis",
    "severity",
    "confidence_ppm",
    "fingerprint",
    "evidence_count",
    "redacted_summary",
    "category",
    "cwe",
    "remediation_id",
    "remediation_summary",
    "evidence_references",
    "control_evidence_references",
    "candidate_evidence_references",
    "case_reference",
    "outcome_reference",
    "verification_stage",
];

#[cfg(feature = "scanning")]
fn render_assessment_csv(
    document: &AssessmentDocument<'_>,
    limit: usize,
) -> Result<String, ReportError> {
    let mut output = RenderBuffer::new(limit);
    write_assessment_csv_row(&mut output, ASSESSMENT_CSV_HEADERS)?;
    let subject_count = document.subject_count.to_string();
    let item_count = document.item_count.to_string();
    write_assessment_csv_row(
        &mut output,
        [
            "document",
            document.schema,
            document.source_schema,
            document.run_schema,
            document.profile_schema,
            document.profile,
            document.status,
            &subject_count,
            &item_count,
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
        ],
    )?;
    #[cfg(feature = "authorization-review")]
    if let Some(audit) = &document.authorization_review {
        let request_count = audit.request_count.to_string();
        let summary = format!(
            "policy_id={};selected_path_count={};ignored_path_count={};primary_stable={};peer_stable={};cross_resources_equivalent={};item_projected={}",
            audit.policy_id,
            audit.selected_path_count,
            audit.ignored_path_count,
            optional_bool_token(audit.primary_stable),
            optional_bool_token(audit.peer_stable),
            optional_bool_token(audit.cross_resources_equivalent),
            audit.item_projected,
        );
        write_assessment_csv_row(
            &mut output,
            [
                "authorization_review_audit",
                audit.schema,
                "",
                "",
                "",
                "",
                audit.outcome,
                "",
                "",
                "",
                audit.capability_id,
                "",
                "",
                if audit.item_projected {
                    "needs_review"
                } else {
                    ""
                },
                if audit.item_projected {
                    "differential"
                } else {
                    ""
                },
                "",
                "",
                "",
                &request_count,
                &summary,
                "authorization-review",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
            ],
        )?;
    }
    #[cfg(feature = "openapi-review")]
    if let Some(audit) = &document.openapi_review {
        let request_count = audit.request_count.to_string();
        let summary = audit.summary();
        write_assessment_csv_row(
            &mut output,
            [
                "openapi_review_audit",
                audit.schema,
                "",
                "",
                "",
                "",
                audit.outcome,
                "",
                "",
                "",
                audit.capability_id,
                "",
                "",
                if audit.item_projected {
                    "informational"
                } else {
                    ""
                },
                if audit.item_projected {
                    "observation"
                } else {
                    ""
                },
                "",
                "",
                "",
                &request_count,
                &summary,
                "api-surface",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
            ],
        )?;
    }
    #[cfg(feature = "rest-review")]
    if let Some(audit) = &document.rest_review {
        let request_count = audit.request_count.to_string();
        let summary = audit.summary();
        write_assessment_csv_row(
            &mut output,
            [
                "rest_readonly_review_audit",
                audit.schema,
                "",
                "",
                "",
                "",
                audit.outcome,
                "",
                "",
                "",
                audit.capability_id,
                "",
                "",
                if audit.item_projected {
                    "informational"
                } else {
                    ""
                },
                if audit.item_projected {
                    "observation"
                } else {
                    ""
                },
                "",
                "",
                "",
                &request_count,
                &summary,
                "api-surface",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
            ],
        )?;
    }
    #[cfg(feature = "wordpress-review")]
    if let Some(audit) = &document.wordpress_review {
        let evidence_count = audit.evidence_reference_count.to_string();
        let summary = audit.wire_json()?;
        write_assessment_csv_row(
            &mut output,
            [
                "wordpress_review_audit",
                audit.schema,
                "",
                "",
                "",
                "",
                audit.catalog_status,
                "",
                "",
                "",
                audit.capability_id,
                "",
                "",
                if audit.item_projected {
                    "informational"
                } else {
                    ""
                },
                if audit.item_projected {
                    "observation"
                } else {
                    ""
                },
                "",
                "",
                "",
                &evidence_count,
                &summary,
                "wordpress-review",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
            ],
        )?;
    }
    #[cfg(feature = "wordpress-review")]
    if let Some(discovery) = &document.wordpress_discovery {
        let evidence_count = discovery
            .sources
            .iter()
            .map(|source| source.evidence_reference_count)
            .sum::<usize>()
            .to_string();
        let summary = discovery.wire_json()?;
        write_assessment_csv_row(
            &mut output,
            [
                "wordpress_discovery_audit",
                discovery.schema,
                "",
                "",
                "",
                "",
                "selected",
                "",
                "",
                "",
                discovery.capability_id,
                "",
                "",
                "informational",
                "observation",
                "",
                "",
                "",
                &evidence_count,
                &summary,
                "wordpress-discovery",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
            ],
        )?;
    }
    for item in &document.items {
        let confidence_ppm = item.confidence_ppm.to_string();
        let evidence_count = item.evidence_count.to_string();
        let evidence_references = item.evidence_references.join(";");
        let control_evidence_references = item.control_evidence_references.join(";");
        let candidate_evidence_references = item.candidate_evidence_references.join(";");
        write_assessment_csv_row(
            &mut output,
            [
                "item",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                item.schema,
                item.capability_id,
                &item.subject_reference,
                item.title,
                item.disposition,
                item.claim_basis,
                item.severity.unwrap_or(""),
                &confidence_ppm,
                item.fingerprint,
                &evidence_count,
                item.redacted_summary,
                item.category,
                item.cwe.unwrap_or(""),
                item.remediation.id,
                item.remediation.summary,
                &evidence_references,
                &control_evidence_references,
                &candidate_evidence_references,
                item.case_reference.as_deref().unwrap_or(""),
                item.outcome_reference.as_deref().unwrap_or(""),
                item.verification_stage.unwrap_or(""),
            ],
        )?;
    }
    Ok(output.finish())
}

#[cfg(feature = "scanning")]
fn write_assessment_csv_row(
    output: &mut RenderBuffer,
    cells: [&str; ASSESSMENT_CSV_HEADERS.len()],
) -> Result<(), ReportError> {
    for (index, cell) in cells.into_iter().enumerate() {
        if index != 0 {
            output.push_char(',')?;
        }
        write_csv_cell(output, cell)?;
    }
    output.push_char('\n')
}

#[cfg(feature = "scanning")]
fn render_assessment_html(
    document: &AssessmentDocument<'_>,
    limit: usize,
) -> Result<String, ReportError> {
    let mut output = RenderBuffer::new(limit);
    output.push_str(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; base-uri 'none'; form-action 'none'\">\
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
<title>Termivar assessment report</title><style>\
:root{color-scheme:light dark}body{font:14px/1.5 system-ui,sans-serif;margin:2rem;max-width:90rem}\
h1,h2,h3{line-height:1.2}.meta{display:grid;grid-template-columns:max-content 1fr;gap:.3rem 1rem}\
.item,.wp-detail{border:1px solid currentColor;padding:1rem;margin-block:1rem}.item dl,.wp-detail dl{display:grid;grid-template-columns:max-content 1fr;gap:.3rem 1rem}\
.disposition{border:2px solid currentColor;display:inline-block;font-weight:700;padding:.15rem .4rem}\
.wp-summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(10rem,1fr));gap:.75rem;margin-block:1rem}\
.wp-card{border:1px solid currentColor;padding:.75rem}.wp-card strong{display:block;font-size:1.4rem}\
.wp-note{border-inline-start:.3rem solid currentColor;padding:.5rem .75rem}.wp-detail summary{cursor:pointer;font-weight:700}\
code,pre{overflow-wrap:anywhere}pre{white-space:pre-wrap}.empty{font-style:italic}@media print{.wp-detail>*{display:block!important}}</style></head><body><main>\
<h1>Termivar assessment report</h1><p><strong>Lifecycle status:</strong> completed typed assessment.</p><dl class=\"meta\">",
    )?;
    for (label, value) in document.metadata() {
        output.push_str("<dt>")?;
        write_html_text(&mut output, label)?;
        output.push_str("</dt><dd><code>")?;
        write_html_text(&mut output, &value)?;
        output.push_str("</code></dd>")?;
    }
    output.push_str("</dl>")?;
    #[cfg(feature = "authorization-review")]
    if let Some(audit) = &document.authorization_review {
        output
            .push_str("<section><h2>Resource authorization review audit</h2><dl class=\"meta\">")?;
        for (label, value) in audit.metadata() {
            output.push_str("<dt>")?;
            write_html_text(&mut output, label)?;
            output.push_str("</dt><dd><code>")?;
            write_html_text(&mut output, &value)?;
            output.push_str("</code></dd>")?;
        }
        output.push_str("</dl></section>")?;
    }
    #[cfg(feature = "openapi-review")]
    if let Some(audit) = &document.openapi_review {
        output.push_str("<section><h2>OpenAPI review audit</h2><dl class=\"meta\">")?;
        for (label, value) in audit.metadata() {
            output.push_str("<dt>")?;
            write_html_text(&mut output, label)?;
            output.push_str("</dt><dd><code>")?;
            write_html_text(&mut output, &value)?;
            output.push_str("</code></dd>")?;
        }
        output.push_str("</dl></section>")?;
    }
    #[cfg(feature = "rest-review")]
    if let Some(audit) = &document.rest_review {
        output.push_str("<section><h2>REST read-only review audit</h2><dl class=\"meta\">")?;
        for (label, value) in audit.metadata() {
            output.push_str("<dt>")?;
            write_html_text(&mut output, label)?;
            output.push_str("</dt><dd><code>")?;
            write_html_text(&mut output, &value)?;
            output.push_str("</code></dd>")?;
        }
        output.push_str("</dl></section>")?;
    }
    #[cfg(feature = "wordpress-review")]
    if let Some(audit) = &document.wordpress_review {
        output.push_str("<section><h2>WordPress evidence review audit</h2><dl class=\"meta\">")?;
        for (label, value) in audit.metadata() {
            output.push_str("<dt>")?;
            write_html_text(&mut output, label)?;
            output.push_str("</dt><dd><code>")?;
            write_html_text(&mut output, &value)?;
            output.push_str("</code></dd>")?;
        }
        output.push_str("</dl>")?;
        write_wordpress_presentation(&mut WordPressPresentationEmitter::Html(&mut output), audit)?;
        write_html_wordpress_external_attribution(&mut output, audit)?;
        output.push_str("</section>")?;
    }
    #[cfg(feature = "wordpress-review")]
    if let Some(discovery) = &document.wordpress_discovery {
        output.push_str(
            "<section><h2>WordPress public metadata discovery audit</h2><dl class=\"meta\">",
        )?;
        for (label, value) in discovery.metadata() {
            output.push_str("<dt>")?;
            write_html_text(&mut output, label)?;
            output.push_str("</dt><dd><code>")?;
            write_html_text(&mut output, &value)?;
            output.push_str("</code></dd>")?;
        }
        output.push_str("</dl>")?;
        write_wordpress_discovery_presentation(
            &mut WordPressPresentationEmitter::Html(&mut output),
            discovery,
        )?;
        output.push_str("</section>")?;
    }
    output.push_str("<section><h2>Assessment items</h2>")?;
    if document.items.is_empty() {
        output.push_str("<p class=\"empty\">No assessment items.</p>")?;
    } else {
        for (index, item) in document.items.iter().enumerate() {
            output.push_fmt(format_args!(
                "<article class=\"item\"><h2>Item {}</h2>",
                index + 1
            ))?;
            output.push_str("<p class=\"disposition\"><span>Disposition: </span><code>")?;
            write_html_text(&mut output, item.disposition)?;
            output.push_str("</code></p><dl>")?;
            for (label, value) in item.required_metadata() {
                output.push_str("<dt>")?;
                write_html_text(&mut output, label)?;
                output.push_str("</dt><dd><code>")?;
                write_html_text(&mut output, &value)?;
                output.push_str("</code></dd>")?;
            }
            output.push_str("<dt>Severity</dt><dd>")?;
            write_html_optional_assessment_text(&mut output, item.severity, "not assigned")?;
            output.push_str("</dd><dt>CWE</dt><dd>")?;
            write_html_optional_assessment_text(&mut output, item.cwe, "not applicable")?;
            output.push_str("</dd></dl></article>")?;
        }
    }
    output.push_str("</section></main></body></html>")?;
    Ok(output.finish())
}

#[cfg(feature = "scanning")]
fn write_html_optional_assessment_text(
    output: &mut RenderBuffer,
    value: Option<&str>,
    absent: &'static str,
) -> Result<(), ReportError> {
    match value {
        Some(value) => {
            output.push_str("<code>")?;
            write_html_text(output, value)?;
            output.push_str("</code>")
        },
        None => {
            output.push_str("<span class=\"empty\">")?;
            write_html_text(output, absent)?;
            output.push_str("</span>")
        },
    }
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
#[derive(Clone, Copy)]
enum WordPressPresentationInline<'a> {
    Literal(&'static str),
    Code(&'a str),
    Count(usize),
    Bytes(u64),
    Bool(bool),
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
enum WordPressPresentationEmitter<'a> {
    Html(&'a mut RenderBuffer),
    Markdown(&'a mut RenderBuffer),
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
fn write_wordpress_presentation(
    emitter: &mut WordPressPresentationEmitter<'_>,
    audit: &AssessmentWordPressAuditDocument,
) -> Result<(), ReportError> {
    let counts = audit.presentation_counts();
    emitter.note(
        "Interpretation boundary: review candidates are source-data comparisons, not confirmed vulnerabilities. Processing completion does not establish exhaustive coverage, exploitability, impact, or remediation.",
    )?;
    emitter.overview(&[
        ("Components", audit.component_count),
        ("Review candidates", counts.review_candidates),
        ("Evaluation limitations", counts.limitations),
        ("Contradicted on supplied facts", counts.contradicted),
        ("Evaluations with source guidance", counts.source_guidance),
    ])?;

    emitter.heading("Source and coverage")?;
    emitter.begin_fields()?;
    wordpress_code_field(emitter, "Catalogue status", audit.catalog_status)?;
    if let Some(catalog) = &audit.catalog {
        wordpress_code_field(emitter, "Catalogue identity", &catalog.id)?;
        wordpress_code_field(emitter, "Catalogue revision", &catalog.revision)?;
        wordpress_code_field(
            emitter,
            "Source-declared retrieval date",
            &catalog.retrieved_on,
        )?;
        if let Some(schema) = audit.catalog_schema {
            wordpress_code_field(emitter, "Catalogue schema", schema)?;
        }
    }
    if let Some(inventory) = &audit.inventory_import {
        wordpress_code_field(emitter, "Core inventory", inventory.coverage.core)?;
        wordpress_code_field(emitter, "Plugin inventory", inventory.coverage.plugins)?;
        wordpress_code_field(emitter, "Theme inventory", inventory.coverage.themes)?;
        wordpress_count_field(
            emitter,
            "Imported inventory components",
            inventory.component_count,
        )?;
        wordpress_count_field(
            emitter,
            "Inventory limitations",
            inventory.limitations.len(),
        )?;
    } else {
        wordpress_code_field(emitter, "Saved inventory coverage", "not supplied")?;
    }
    if let Some(external) = &audit.external_review {
        wordpress_code_field(
            emitter,
            "Advisory source namespace",
            external.source_namespace,
        )?;
        wordpress_code_field(emitter, "Advisory source format", external.source_format)?;
        wordpress_code_field(emitter, "Normalization mapping", external.mapping_revision)?;
        if let Some(policy) = external.identity_mapping_policy {
            wordpress_code_field(emitter, "Identity mapping policy", policy)?;
            wordpress_optional_code_field(
                emitter,
                "Source identity assurance",
                external.identity_source_assurance,
            )?;
        }
        if let Some(policy) = external.resource_policy {
            wordpress_code_field(emitter, "External resource policy", policy)?;
        }
        wordpress_code_field(emitter, "Comparison policy", external.comparison_policy)?;
        if let Some(profile) = external.comparison_profile {
            wordpress_code_field(emitter, "Comparison profile", profile)?;
            wordpress_optional_code_field(emitter, "Policy selection", external.policy_selection)?;
            wordpress_optional_code_field(
                emitter,
                "Source comparison semantics assurance",
                external.source_semantics_assurance,
            )?;
        }
        wordpress_bytes_field(emitter, "Input bytes", external.input.byte_length)?;
        wordpress_code_field(emitter, "Input byte digest", &external.input.sha256)?;
        wordpress_code_field(
            emitter,
            "Input semantic digest",
            &external.input.semantic_sha256,
        )?;
        if let Some(bytes) = external.input.accounted_retained_bytes {
            wordpress_count_field(emitter, "Accounted retained import bytes", bytes)?;
        }
        for (label, count) in [
            ("Parsed source records", external.counts.parsed_records),
            (
                "Software associations",
                external.counts.software_associations,
            ),
            (
                "Relevant associations",
                external.counts.selected_associations,
            ),
            (
                "Evaluable associations",
                external.counts.evaluable_associations,
            ),
        ] {
            wordpress_count_field(emitter, label, count)?;
        }
        for (label, count) in [
            (
                "Exact source identity associations",
                external.counts.exact_identity_associations,
            ),
            (
                "Case-fold candidate associations",
                external.counts.candidate_identity_associations,
            ),
            (
                "Case-fold ambiguous associations",
                external.counts.ambiguous_identity_associations,
            ),
            (
                "Unresolved source identity associations",
                external.counts.unresolved_identity_associations,
            ),
            (
                "Detailed unresolved identity rows shown",
                external.counts.projected_identity_limitations,
            ),
            (
                "Unresolved identity rows not expanded",
                external.counts.unprojected_identity_limitations,
            ),
        ] {
            if let Some(count) = count {
                wordpress_count_field(emitter, label, count)?;
            }
        }
        if external.comparison_profile.is_none() {
            wordpress_count_field(
                emitter,
                "Unsupported relevant associations",
                external.counts.unsupported_associations,
            )?;
        }
        wordpress_count_field(
            emitter,
            if external.identity_mapping_policy.is_some() {
                "Mapped associations not selected for supplied components"
            } else {
                "Irrelevant associations excluded"
            },
            external
                .counts
                .mapped_unselected_associations
                .unwrap_or(external.counts.excluded_associations),
        )?;
        for (label, count) in [
            (
                "Within-range associations",
                external.counts.within_associations,
            ),
            (
                "Outside-range associations",
                external.counts.outside_associations,
            ),
            (
                "Indeterminate associations",
                external.counts.indeterminate_associations,
            ),
            ("Selected source ranges", external.counts.selected_ranges),
            ("Evaluated ranges", external.counts.evaluated_ranges),
            ("Containing ranges", external.counts.containing_ranges),
            ("Noncontaining ranges", external.counts.noncontaining_ranges),
            ("Unsupported ranges", external.counts.unsupported_ranges),
            ("Invalid ranges", external.counts.invalid_ranges),
            ("Ranges not evaluated", external.counts.not_evaluated_ranges),
            (
                "Qualified partial-range matches",
                external.counts.partial_range_coverage_associations,
            ),
        ] {
            if let Some(count) = count {
                wordpress_count_field(emitter, label, count)?;
            }
        }
    }
    emitter.end_fields()?;

    if let Some(inventory) = &audit.inventory_import {
        emitter.heading("Saved inventory provenance and limitations")?;
        for input in &inventory.inputs {
            emitter.begin_record()?;
            emitter.inline(WordPressPresentationInline::Code(input.class))?;
            emitter.end_record_title()?;
            wordpress_count_field(emitter, "Exact-read bytes", input.byte_length)?;
            wordpress_code_field(emitter, "SHA-256", &input.sha256)?;
            emitter.end_record()?;
        }
        if inventory.limitations.is_empty() {
            emitter.empty("No typed inventory-row limitations were recorded.")?;
        } else {
            for limitation in &inventory.limitations {
                emitter.begin_record()?;
                emitter.inline(WordPressPresentationInline::Literal(
                    "Unsupported inventory row: ",
                ))?;
                emitter.inline(WordPressPresentationInline::Code(&limitation.declared_name))?;
                emitter.end_record_title()?;
                wordpress_code_field(emitter, "Status", limitation.status)?;
                wordpress_code_field(emitter, "Reason", limitation.reason)?;
                wordpress_optional_code_field(
                    emitter,
                    "Declared version",
                    limitation.version.as_deref(),
                )?;
                emitter.end_record()?;
            }
        }
    }

    emitter.heading("Component evidence")?;
    if audit.components.is_empty() {
        emitter.empty("No component evidence was retained.")?;
    } else {
        for component in &audit.components {
            write_wordpress_component(emitter, component)?;
        }
    }

    emitter.heading("Execution boundary")?;
    emitter.paragraph(
        "The WordPress review interprets retained and operator-supplied data only; it does not execute an exploit or validate impact.",
    )?;
    emitter.begin_fields()?;
    wordpress_code_field(emitter, "Exploit execution", "not_performed")?;
    wordpress_code_field(emitter, "Impact validation", "not_performed")?;
    emitter.end_fields()?;

    write_wordpress_evaluation_group(
        emitter,
        audit,
        WordPressPresentationGroup::ReviewCandidate,
        "Review candidates",
        "These records match only on the supplied declarations and still require operator review.",
    )?;
    write_wordpress_evaluation_group(
        emitter,
        audit,
        WordPressPresentationGroup::Contradicted,
        "Contradicted on supplied facts",
        "These declared-data evaluations did not match; they do not establish that the installation is safe.",
    )?;
    write_wordpress_evaluation_group(
        emitter,
        audit,
        WordPressPresentationGroup::Limitation,
        "Evaluation limitations",
        "Missing, conflicting, unsupported, or source-semantics-limited data prevented a stronger evaluation.",
    )?;

    emitter.heading("Source-declared remediation information")?;
    emitter.note(
        "Source-declared fixed versions, patched versions, and remediation remain attached to each evaluation above. They are not an automatic update, a verified fix, or a minimum safe version across every maintained branch. A false source patched flag means only that the association did not declare a fix; it does not establish permanent unpatchability.",
    )?;
    emitter.begin_fields()?;
    wordpress_count_field(
        emitter,
        "Evaluations with source guidance",
        counts.source_guidance,
    )?;
    emitter.end_fields()
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
fn write_wordpress_discovery_presentation(
    emitter: &mut WordPressPresentationEmitter<'_>,
    discovery: &AssessmentWordPressDiscoveryAuditDocument,
) -> Result<(), ReportError> {
    emitter.note(
        "Discovery boundary: these anonymous same-origin metadata responses are source-qualified public declarations. They do not authenticate installed state, prove vulnerability applicability, or perform exploitation or impact validation.",
    )?;
    emitter.overview(&[
        ("Root-derived seeds", usize::from(discovery.seed_count)),
        (
            "Selected candidates",
            usize::from(discovery.candidate_count),
        ),
        (
            "Attempted requests",
            usize::from(discovery.attempted_request_count),
        ),
        (
            "Completed responses",
            usize::from(discovery.completed_response_count),
        ),
        (
            "Committed responses",
            usize::from(discovery.committed_response_count),
        ),
    ])?;
    emitter.heading("Discovered metadata sources")?;
    if discovery.sources.is_empty() {
        emitter
            .empty("No eligible metadata source was selected from the committed root response.")?;
        return Ok(());
    }
    for source in &discovery.sources {
        emitter.begin_record()?;
        emitter.inline(WordPressPresentationInline::Code(source.kind))?;
        if let Some(component) = &source.component {
            emitter.inline(WordPressPresentationInline::Literal(" — "))?;
            emitter.inline(WordPressPresentationInline::Code(component.kind))?;
            emitter.inline(WordPressPresentationInline::Literal(":"))?;
            emitter.inline(WordPressPresentationInline::Code(&component.slug))?;
        }
        emitter.inline(WordPressPresentationInline::Literal(" — "))?;
        emitter.inline(WordPressPresentationInline::Code(source.outcome))?;
        emitter.end_record_title()?;
        wordpress_code_field(emitter, "Source class", source.kind)?;
        wordpress_code_field(emitter, "Collection outcome", source.outcome)?;
        wordpress_count_field(
            emitter,
            "Parent-theme depth",
            usize::from(source.parent_depth),
        )?;
        wordpress_count_field(
            emitter,
            "Evidence reference count",
            source.evidence_reference_count,
        )?;
        emitter.begin_field("Response bytes")?;
        emitter.inline(WordPressPresentationInline::Bytes(source.response_bytes))?;
        emitter.end_field()?;
        write_wordpress_values(
            emitter,
            "REST namespaces (protocol support only)",
            source.namespaces.iter().map(String::as_str),
            "none retained",
        )?;
        if let Some(theme) = &source.theme {
            wordpress_optional_code_field(emitter, "Theme display name", theme.name.as_deref())?;
            wordpress_optional_code_field(
                emitter,
                "Artifact-declared theme version",
                theme.version.as_deref(),
            )?;
            wordpress_optional_code_field(
                emitter,
                "Declared parent theme slug",
                theme.template.as_deref(),
            )?;
            wordpress_optional_code_field(
                emitter,
                "Requires WordPress",
                theme.requires_wordpress.as_deref(),
            )?;
            wordpress_optional_code_field(
                emitter,
                "Requires PHP (compatibility declaration)",
                theme.requires_php.as_deref(),
            )?;
            wordpress_optional_code_field(
                emitter,
                "Tested up to (compatibility declaration)",
                theme.tested_up_to.as_deref(),
            )?;
        }
        if let Some(plugin) = &source.plugin {
            wordpress_optional_code_field(emitter, "Plugin display name", plugin.name.as_deref())?;
            wordpress_optional_code_field(
                emitter,
                "Distribution release hint (not installed version)",
                plugin.stable_tag.as_deref(),
            )?;
            wordpress_optional_code_field(
                emitter,
                "Requires WordPress",
                plugin.requires_wordpress.as_deref(),
            )?;
            wordpress_optional_code_field(
                emitter,
                "Requires PHP (compatibility declaration)",
                plugin.requires_php.as_deref(),
            )?;
            wordpress_optional_code_field(
                emitter,
                "Tested up to (compatibility declaration)",
                plugin.tested_up_to.as_deref(),
            )?;
        }
        emitter.end_record()?;
    }
    Ok(())
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
fn write_wordpress_component(
    emitter: &mut WordPressPresentationEmitter<'_>,
    component: &WordPressComponentDocument,
) -> Result<(), ReportError> {
    emitter.begin_record()?;
    emitter.inline(WordPressPresentationInline::Code(component.identity.kind))?;
    emitter.inline(WordPressPresentationInline::Literal(":"))?;
    emitter.inline(WordPressPresentationInline::Code(&component.identity.slug))?;
    emitter.inline(WordPressPresentationInline::Literal(" — "))?;
    emitter.inline(WordPressPresentationInline::Code(component.evidence_class))?;
    emitter.end_record_title()?;
    wordpress_code_field(emitter, "Evidence class", component.evidence_class)?;
    wordpress_optional_code_field(emitter, "Activation", component.activation)?;
    wordpress_optional_code_field(emitter, "Inventory status", component.inventory_status)?;
    write_wordpress_values(
        emitter,
        "Identity sources",
        component.identity_sources.iter().copied(),
        "none recorded",
    )?;
    write_wordpress_values(
        emitter,
        "Confidence classes",
        component.confidence_classes.iter().copied(),
        "none recorded",
    )?;
    if component.versions.is_empty() {
        wordpress_code_field(emitter, "Version evidence", "missing")?;
    } else {
        emitter.begin_list_field("Version evidence")?;
        for version in &component.versions {
            emitter.begin_list_item()?;
            emitter.inline(WordPressPresentationInline::Code(&version.value))?;
            emitter.inline(WordPressPresentationInline::Literal(" from "))?;
            emitter.inline(WordPressPresentationInline::Code(version.source))?;
            emitter.inline(WordPressPresentationInline::Literal(" with "))?;
            emitter.inline(WordPressPresentationInline::Code(version.confidence))?;
            emitter.end_list_item()?;
        }
        emitter.end_list_field()?;
    }
    emitter.end_record()
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
fn write_wordpress_evaluation_group(
    emitter: &mut WordPressPresentationEmitter<'_>,
    audit: &AssessmentWordPressAuditDocument,
    group: WordPressPresentationGroup,
    title: &'static str,
    explanation: &'static str,
) -> Result<(), ReportError> {
    emitter.heading(title)?;
    emitter.paragraph(explanation)?;
    let mut rendered = 0_usize;
    for advisory in &audit.advisories {
        if wordpress_advisory_group(advisory) == group {
            write_wordpress_advisory(emitter, advisory)?;
            rendered += 1;
        }
    }
    if let Some(external) = &audit.external_review {
        for evaluation in &external.evaluations {
            if wordpress_external_advisory_group(evaluation) == group {
                write_wordpress_external_evaluation(emitter, external, evaluation)?;
                rendered += 1;
            }
        }
        if group == WordPressPresentationGroup::Limitation {
            if let Some(limitations) = &external.identity_limitations {
                for limitation in limitations {
                    write_wordpress_external_identity_limitation(emitter, limitation)?;
                    rendered += 1;
                }
            }
            if external
                .counts
                .unprojected_identity_limitations
                .is_some_and(|count| count > 0)
            {
                emitter.paragraph(
                    "The unresolved identity total covers the complete imported snapshot. This section expands only a deterministic bounded detail projection; rows not expanded here were not evaluated or classified as unaffected.",
                )?;
            }
        }
    }
    if rendered == 0 {
        emitter.empty("No records in this group.")?;
    }
    Ok(())
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
fn write_wordpress_advisory(
    emitter: &mut WordPressPresentationEmitter<'_>,
    advisory: &WordPressAdvisoryDocument,
) -> Result<(), ReportError> {
    emitter.begin_record()?;
    emitter.inline(WordPressPresentationInline::Code(&advisory.id))?;
    emitter.inline(WordPressPresentationInline::Literal(" — "))?;
    emitter.inline(WordPressPresentationInline::Code(advisory.component.kind))?;
    emitter.inline(WordPressPresentationInline::Literal(":"))?;
    emitter.inline(WordPressPresentationInline::Code(&advisory.component.slug))?;
    emitter.inline(WordPressPresentationInline::Literal(" — "))?;
    emitter.inline(WordPressPresentationInline::Code(advisory.applicability))?;
    emitter.end_record_title()?;
    wordpress_code_field(emitter, "Applicability", advisory.applicability)?;
    wordpress_code_field(emitter, "Version relation", advisory.version_relation)?;
    wordpress_code_field(
        emitter,
        "Comparison profile",
        advisory
            .comparison_profile
            .unwrap_or("numeric-dotted/v1 (implicit catalogue contract)"),
    )?;
    wordpress_code_field(
        emitter,
        "Version resolution",
        advisory
            .version_resolution
            .unwrap_or("not recorded by audit schema"),
    )?;
    wordpress_code_field(
        emitter,
        "Version-resolution reason",
        advisory
            .version_resolution_reason
            .unwrap_or("not recorded by audit schema"),
    )?;
    wordpress_code_field(emitter, "Component evidence", advisory.component_evidence)?;
    wordpress_code_field(emitter, "Source reference", &advisory.source.reference)?;
    wordpress_code_field(emitter, "Source revision", &advisory.source.revision)?;
    wordpress_code_field(
        emitter,
        "Source-declared retrieval date",
        &advisory.source.retrieved_on,
    )?;
    wordpress_code_field(emitter, "Source usage basis", &advisory.source.usage_basis)?;
    wordpress_optional_code_field(emitter, "CVE", advisory.cve.as_deref())?;
    wordpress_code_field(emitter, "Source summary", &advisory.summary)?;
    if advisory.affected_ranges.is_empty() {
        wordpress_code_field(emitter, "Affected ranges", "none declared")?;
    } else {
        emitter.begin_list_field("Affected ranges")?;
        for range in &advisory.affected_ranges {
            emitter.begin_list_item()?;
            emitter.inline(WordPressPresentationInline::Literal("lower "))?;
            write_wordpress_endpoint(emitter, range.lower.as_ref())?;
            emitter.inline(WordPressPresentationInline::Literal("; upper "))?;
            write_wordpress_endpoint(emitter, range.upper.as_ref())?;
            emitter.end_list_item()?;
        }
        emitter.end_list_field()?;
    }
    write_wordpress_values(
        emitter,
        "Source-declared fixed versions",
        advisory.fixed_versions.iter().map(String::as_str),
        "none declared",
    )?;
    if advisory.prerequisites.is_empty() {
        wordpress_code_field(emitter, "Prerequisites", "none declared")?;
    } else {
        emitter.begin_list_field("Prerequisites")?;
        for prerequisite in &advisory.prerequisites {
            emitter.begin_list_item()?;
            emitter.inline(WordPressPresentationInline::Code(prerequisite.kind))?;
            emitter.inline(WordPressPresentationInline::Literal(" expected "))?;
            emitter.inline(WordPressPresentationInline::Code(&prerequisite.expected))?;
            emitter.inline(WordPressPresentationInline::Literal(": "))?;
            emitter.inline(WordPressPresentationInline::Code(prerequisite.outcome))?;
            if let Some(patch_id) = &prerequisite.patch_id {
                emitter.inline(WordPressPresentationInline::Literal("; patch "))?;
                emitter.inline(WordPressPresentationInline::Code(patch_id))?;
            }
            emitter.end_list_item()?;
        }
        emitter.end_list_field()?;
    }
    wordpress_optional_code_field(
        emitter,
        "Source-declared remediation",
        advisory.remediation.as_deref(),
    )?;
    emitter.end_record()
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
fn write_wordpress_endpoint(
    emitter: &mut WordPressPresentationEmitter<'_>,
    endpoint: Option<&WordPressVersionEndpointDocument>,
) -> Result<(), ReportError> {
    if let Some(endpoint) = endpoint {
        emitter.inline(WordPressPresentationInline::Code(&endpoint.declared))?;
        emitter.inline(WordPressPresentationInline::Literal(
            if endpoint.inclusive {
                " (inclusive)"
            } else {
                " (exclusive)"
            },
        ))
    } else {
        emitter.inline(WordPressPresentationInline::Code("unbounded/unknown"))
    }
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
fn write_wordpress_external_evaluation(
    emitter: &mut WordPressPresentationEmitter<'_>,
    external: &WordPressExternalReviewDocument,
    evaluation: &WordPressExternalEvaluationDocument,
) -> Result<(), ReportError> {
    emitter.begin_record()?;
    emitter.inline(WordPressPresentationInline::Code(
        &evaluation.key.upstream_id,
    ))?;
    emitter.inline(WordPressPresentationInline::Literal(" — "))?;
    emitter.inline(WordPressPresentationInline::Code(
        evaluation.key.component.kind,
    ))?;
    emitter.inline(WordPressPresentationInline::Literal(":"))?;
    emitter.inline(WordPressPresentationInline::Code(
        &evaluation.key.component.slug,
    ))?;
    emitter.inline(WordPressPresentationInline::Literal(" — "))?;
    emitter.inline(WordPressPresentationInline::Code(evaluation.applicability))?;
    emitter.end_record_title()?;
    wordpress_code_field(
        emitter,
        "Source namespace",
        &evaluation.key.source_namespace,
    )?;
    if let Some(source_component) = &evaluation.key.source_component {
        emitter.begin_field("Raw source component identity")?;
        emitter.inline(WordPressPresentationInline::Code(source_component.kind))?;
        emitter.inline(WordPressPresentationInline::Literal(":"))?;
        emitter.inline(WordPressPresentationInline::Code(&source_component.slug))?;
        emitter.end_field()?;
        wordpress_optional_code_field(emitter, "Identity mapping", evaluation.identity_mapping)?;
        if let Some(count) = evaluation.identity_collision_raw_count {
            wordpress_count_field(emitter, "Colliding raw source identities", count)?;
        }
    }
    wordpress_code_field(emitter, "Source title", &evaluation.title)?;
    wordpress_code_field(emitter, "Source component name", &evaluation.display_name)?;
    wordpress_bool_field(
        emitter,
        "Source informational classification",
        evaluation.informational,
    )?;
    wordpress_code_field(emitter, "Source description", &evaluation.description)?;
    wordpress_code_field(emitter, "Comparison policy", external.comparison_policy)?;
    if let Some(profile) = external.comparison_profile {
        wordpress_code_field(emitter, "Comparison profile", profile)?;
        wordpress_optional_code_field(emitter, "Policy selection", external.policy_selection)?;
        wordpress_optional_code_field(
            emitter,
            "Source comparison semantics assurance",
            external.source_semantics_assurance,
        )?;
    }
    wordpress_code_field(emitter, "Applicability", evaluation.applicability)?;
    wordpress_code_field(emitter, "Version relation", evaluation.version_relation)?;
    if external.comparison_profile.is_some() {
        wordpress_optional_code_field(
            emitter,
            "Version-relation reason",
            evaluation.version_relation_reason,
        )?;
    }
    wordpress_code_field(
        emitter,
        "Version evidence resolution",
        evaluation.version_evidence_resolution.status,
    )?;
    emitter.begin_field("Version evidence rows / distinct spellings")?;
    emitter.inline(WordPressPresentationInline::Count(
        evaluation.version_evidence_resolution.evidence_row_count,
    ))?;
    emitter.inline(WordPressPresentationInline::Literal(" / "))?;
    emitter.inline(WordPressPresentationInline::Count(
        evaluation
            .version_evidence_resolution
            .distinct_spelling_count,
    ))?;
    emitter.end_field()?;
    if external.comparison_profile.is_some() {
        wordpress_optional_code_field(
            emitter,
            "Semantic version resolution",
            evaluation.version_evidence_resolution.semantic_status,
        )?;
        wordpress_optional_code_field(
            emitter,
            "Semantic resolution reason",
            evaluation.version_evidence_resolution.semantic_reason,
        )?;
    }
    wordpress_code_field(emitter, "Component evidence", evaluation.component_evidence)?;
    wordpress_optional_code_field(emitter, "CVE", evaluation.cve.as_deref())?;
    wordpress_optional_code_field(
        emitter,
        "Source CVE reference",
        evaluation.cve_link.as_deref(),
    )?;
    if let Some(cwe) = &evaluation.cwe {
        emitter.begin_field("Source CWE metadata")?;
        emitter.inline(WordPressPresentationInline::Literal("CWE-"))?;
        emitter.inline(WordPressPresentationInline::Bytes(u64::from(cwe.id)))?;
        emitter.inline(WordPressPresentationInline::Literal(" / "))?;
        emitter.inline(WordPressPresentationInline::Code(&cwe.name))?;
        emitter.end_field()?;
        wordpress_code_field(emitter, "Source CWE description", &cwe.description)?;
    } else {
        wordpress_code_field(emitter, "Source CWE metadata", "not declared")?;
    }
    if let Some(cvss) = &evaluation.cvss {
        emitter.begin_field("Source-declared CVSS metadata")?;
        emitter.inline(WordPressPresentationInline::Code(&cvss.score))?;
        emitter.inline(WordPressPresentationInline::Literal(" / "))?;
        emitter.inline(WordPressPresentationInline::Code(cvss.rating))?;
        emitter.inline(WordPressPresentationInline::Literal(" / "))?;
        emitter.inline(WordPressPresentationInline::Code(&cvss.vector))?;
        emitter.end_field()?;
    } else {
        wordpress_code_field(emitter, "Source-declared CVSS metadata", "not declared")?;
    }
    wordpress_optional_code_field(
        emitter,
        "Source published date",
        evaluation.source_dates.published.as_deref(),
    )?;
    wordpress_optional_code_field(
        emitter,
        "Source updated date",
        evaluation.source_dates.updated.as_deref(),
    )?;
    write_wordpress_values(
        emitter,
        "Source bibliography",
        evaluation.references.iter().map(String::as_str),
        "none declared",
    )?;
    write_wordpress_values(
        emitter,
        "Source researchers",
        evaluation.researchers.iter().map(String::as_str),
        "none declared",
    )?;
    write_wordpress_values(
        emitter,
        "Source notice identifiers",
        evaluation.notice_ids.iter().map(String::as_str),
        "none declared",
    )?;
    if evaluation.affected_ranges.is_empty() {
        wordpress_code_field(emitter, "Source-declared affected ranges", "none declared")?;
    } else {
        emitter.begin_list_field("Source-declared affected ranges")?;
        for (index, range) in evaluation.affected_ranges.iter().enumerate() {
            emitter.begin_list_item()?;
            emitter.inline(WordPressPresentationInline::Code(&range.label))?;
            emitter.inline(WordPressPresentationInline::Literal(": "))?;
            emitter.inline(WordPressPresentationInline::Code(range.from_kind))?;
            emitter.inline(WordPressPresentationInline::Literal(" "))?;
            emitter.inline(WordPressPresentationInline::Code(&range.from_version))?;
            emitter.inline(WordPressPresentationInline::Literal(
                if range.from_inclusive {
                    " inclusive to "
                } else {
                    " exclusive to "
                },
            ))?;
            emitter.inline(WordPressPresentationInline::Code(range.to_kind))?;
            emitter.inline(WordPressPresentationInline::Literal(" "))?;
            emitter.inline(WordPressPresentationInline::Code(&range.to_version))?;
            emitter.inline(WordPressPresentationInline::Literal(
                if range.to_inclusive {
                    " inclusive"
                } else {
                    " exclusive"
                },
            ))?;
            if let Some(interpreted) = evaluation
                .range_evaluations
                .as_ref()
                .and_then(|ranges| ranges.get(index))
            {
                emitter.inline(WordPressPresentationInline::Literal("; Termivar relation "))?;
                emitter.inline(WordPressPresentationInline::Code(interpreted.relation))?;
                emitter.inline(WordPressPresentationInline::Literal(" ("))?;
                emitter.inline(WordPressPresentationInline::Code(interpreted.reason))?;
                emitter.inline(WordPressPresentationInline::Literal(")"))?;
            }
            emitter.end_list_item()?;
        }
        emitter.end_list_field()?;
    }
    wordpress_bool_field(emitter, "Source patched flag", evaluation.source_patched)?;
    write_wordpress_values(
        emitter,
        "Source-declared patched versions",
        evaluation
            .source_patched_versions
            .iter()
            .map(String::as_str),
        "none declared",
    )?;
    wordpress_code_field(
        emitter,
        "Source-declared remediation",
        &evaluation.source_remediation,
    )?;
    emitter.end_record()
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
fn write_wordpress_external_identity_limitation(
    emitter: &mut WordPressPresentationEmitter<'_>,
    limitation: &WordPressExternalIdentityLimitationDocument,
) -> Result<(), ReportError> {
    emitter.begin_record()?;
    emitter.inline(WordPressPresentationInline::Code(
        &limitation.key.upstream_id,
    ))?;
    emitter.inline(WordPressPresentationInline::Literal(" — "))?;
    emitter.inline(WordPressPresentationInline::Code(
        limitation.key.source_component.kind,
    ))?;
    emitter.inline(WordPressPresentationInline::Literal(":"))?;
    emitter.inline(WordPressPresentationInline::Code(
        &limitation.key.source_component.slug,
    ))?;
    emitter.inline(WordPressPresentationInline::Literal(" — "))?;
    emitter.inline(WordPressPresentationInline::Code(limitation.applicability))?;
    emitter.end_record_title()?;
    wordpress_code_field(emitter, "Source namespace", limitation.key.source_namespace)?;
    wordpress_code_field(
        emitter,
        "Raw source component identity",
        &format!(
            "{}:{}",
            limitation.key.source_component.kind, limitation.key.source_component.slug
        ),
    )?;
    wordpress_code_field(
        emitter,
        "Identity resolution",
        limitation.identity_resolution,
    )?;
    wordpress_code_field(emitter, "Source title", &limitation.title)?;
    wordpress_code_field(emitter, "Source component name", &limitation.display_name)?;
    wordpress_code_field(emitter, "Applicability", limitation.applicability)?;
    wordpress_code_field(emitter, "Version relation", limitation.version_relation)?;
    wordpress_code_field(
        emitter,
        "Version-relation reason",
        limitation.version_relation_reason,
    )?;
    write_wordpress_values(
        emitter,
        "Source bibliography",
        limitation.references.iter().map(String::as_str),
        "none declared",
    )?;
    write_wordpress_values(
        emitter,
        "Source notice identifiers",
        limitation.notice_ids.iter().map(String::as_str),
        "none declared",
    )?;
    if limitation.affected_ranges.is_empty() {
        wordpress_code_field(emitter, "Source-declared affected ranges", "none declared")?;
    } else {
        emitter.begin_list_field("Source-declared affected ranges")?;
        for (range, interpretation) in limitation
            .affected_ranges
            .iter()
            .zip(&limitation.range_evaluations)
        {
            emitter.begin_list_item()?;
            emitter.inline(WordPressPresentationInline::Code(&range.label))?;
            emitter.inline(WordPressPresentationInline::Literal(": "))?;
            emitter.inline(WordPressPresentationInline::Code(range.from_kind))?;
            emitter.inline(WordPressPresentationInline::Literal(" "))?;
            emitter.inline(WordPressPresentationInline::Code(&range.from_version))?;
            emitter.inline(WordPressPresentationInline::Literal(
                if range.from_inclusive {
                    " inclusive to "
                } else {
                    " exclusive to "
                },
            ))?;
            emitter.inline(WordPressPresentationInline::Code(range.to_kind))?;
            emitter.inline(WordPressPresentationInline::Literal(" "))?;
            emitter.inline(WordPressPresentationInline::Code(&range.to_version))?;
            emitter.inline(WordPressPresentationInline::Literal(
                if range.to_inclusive {
                    " inclusive"
                } else {
                    " exclusive"
                },
            ))?;
            emitter.inline(WordPressPresentationInline::Literal("; Termivar relation "))?;
            emitter.inline(WordPressPresentationInline::Code(interpretation.relation))?;
            emitter.inline(WordPressPresentationInline::Literal(" ("))?;
            emitter.inline(WordPressPresentationInline::Code(interpretation.reason))?;
            emitter.inline(WordPressPresentationInline::Literal(")"))?;
            emitter.end_list_item()?;
        }
        emitter.end_list_field()?;
    }
    wordpress_bool_field(emitter, "Source patched flag", limitation.source_patched)?;
    write_wordpress_values(
        emitter,
        "Source-declared patched versions",
        limitation
            .source_patched_versions
            .iter()
            .map(String::as_str),
        "none declared",
    )?;
    wordpress_code_field(
        emitter,
        "Source-declared remediation",
        &limitation.source_remediation,
    )?;
    emitter.end_record()
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
fn wordpress_code_field(
    emitter: &mut WordPressPresentationEmitter<'_>,
    label: &'static str,
    value: &str,
) -> Result<(), ReportError> {
    emitter.begin_field(label)?;
    emitter.inline(WordPressPresentationInline::Code(value))?;
    emitter.end_field()
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
fn wordpress_optional_code_field(
    emitter: &mut WordPressPresentationEmitter<'_>,
    label: &'static str,
    value: Option<&str>,
) -> Result<(), ReportError> {
    wordpress_code_field(emitter, label, value.unwrap_or("not declared"))
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
fn wordpress_count_field(
    emitter: &mut WordPressPresentationEmitter<'_>,
    label: &'static str,
    value: usize,
) -> Result<(), ReportError> {
    emitter.begin_field(label)?;
    emitter.inline(WordPressPresentationInline::Count(value))?;
    emitter.end_field()
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
fn wordpress_bytes_field(
    emitter: &mut WordPressPresentationEmitter<'_>,
    label: &'static str,
    value: u64,
) -> Result<(), ReportError> {
    emitter.begin_field(label)?;
    emitter.inline(WordPressPresentationInline::Bytes(value))?;
    emitter.end_field()
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
fn wordpress_bool_field(
    emitter: &mut WordPressPresentationEmitter<'_>,
    label: &'static str,
    value: bool,
) -> Result<(), ReportError> {
    emitter.begin_field(label)?;
    emitter.inline(WordPressPresentationInline::Bool(value))?;
    emitter.end_field()
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
fn write_wordpress_values<'a, I>(
    emitter: &mut WordPressPresentationEmitter<'_>,
    label: &'static str,
    values: I,
    empty: &'static str,
) -> Result<(), ReportError>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut values = values.into_iter();
    let Some(first) = values.next() else {
        return wordpress_code_field(emitter, label, empty);
    };
    emitter.begin_list_field(label)?;
    emitter.begin_list_item()?;
    emitter.inline(WordPressPresentationInline::Code(first))?;
    emitter.end_list_item()?;
    for value in values {
        emitter.begin_list_item()?;
        emitter.inline(WordPressPresentationInline::Code(value))?;
        emitter.end_list_item()?;
    }
    emitter.end_list_field()
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
impl WordPressPresentationEmitter<'_> {
    fn inline(&mut self, value: WordPressPresentationInline<'_>) -> Result<(), ReportError> {
        match self {
            Self::Html(output) => match value {
                WordPressPresentationInline::Literal(value) => output.push_str(value),
                WordPressPresentationInline::Code(value) => {
                    output.push_str("<code>")?;
                    write_html_text(output, value)?;
                    output.push_str("</code>")
                },
                WordPressPresentationInline::Count(value) => {
                    output.push_fmt(format_args!("{value}"))
                },
                WordPressPresentationInline::Bytes(value) => {
                    output.push_fmt(format_args!("{value}"))
                },
                WordPressPresentationInline::Bool(value) => {
                    output.push_str(if value { "true" } else { "false" })
                },
            },
            Self::Markdown(output) => match value {
                WordPressPresentationInline::Literal(value) => output.push_str(value),
                WordPressPresentationInline::Code(value) => write_markdown_code_span(output, value),
                WordPressPresentationInline::Count(value) => {
                    output.push_fmt(format_args!("{value}"))
                },
                WordPressPresentationInline::Bytes(value) => {
                    output.push_fmt(format_args!("{value}"))
                },
                WordPressPresentationInline::Bool(value) => {
                    output.push_str(if value { "true" } else { "false" })
                },
            },
        }
    }

    fn heading(&mut self, title: &'static str) -> Result<(), ReportError> {
        match self {
            Self::Html(output) => {
                output.push_str("<h3>")?;
                write_html_text(output, title)?;
                output.push_str("</h3>")
            },
            Self::Markdown(output) => {
                output.push_str("\n### ")?;
                output.push_str(title)?;
                output.push_str("\n\n")
            },
        }
    }

    fn paragraph(&mut self, text: &'static str) -> Result<(), ReportError> {
        match self {
            Self::Html(output) => {
                output.push_str("<p>")?;
                write_html_text(output, text)?;
                output.push_str("</p>")
            },
            Self::Markdown(output) => {
                output.push_str(text)?;
                output.push_str("\n\n")
            },
        }
    }

    fn note(&mut self, text: &'static str) -> Result<(), ReportError> {
        match self {
            Self::Html(output) => {
                output.push_str("<p class=\"wp-note\">")?;
                write_html_text(output, text)?;
                output.push_str("</p>")
            },
            Self::Markdown(output) => {
                output.push_str("\n> ")?;
                output.push_str(text)?;
                output.push_str("\n\n")
            },
        }
    }

    fn overview(&mut self, cards: &[(&'static str, usize)]) -> Result<(), ReportError> {
        match self {
            Self::Html(output) => {
                output.push_str("<div class=\"wp-summary\">")?;
                for (label, count) in cards {
                    output.push_str("<div class=\"wp-card\"><strong>")?;
                    output.push_fmt(format_args!("{count}"))?;
                    output.push_str("</strong><span>")?;
                    write_html_text(output, label)?;
                    output.push_str("</span></div>")?;
                }
                output.push_str("</div>")
            },
            Self::Markdown(output) => {
                output.push_str("### Overview\n\n")?;
                for (label, count) in cards {
                    output.push_fmt(format_args!("- {label}: `{count}`\n"))?;
                }
                output.push_char('\n')
            },
        }
    }

    fn begin_fields(&mut self) -> Result<(), ReportError> {
        match self {
            Self::Html(output) => output.push_str("<dl class=\"meta\">"),
            Self::Markdown(_) => Ok(()),
        }
    }

    fn end_fields(&mut self) -> Result<(), ReportError> {
        match self {
            Self::Html(output) => output.push_str("</dl>"),
            Self::Markdown(output) => output.push_char('\n'),
        }
    }

    fn begin_field(&mut self, label: &'static str) -> Result<(), ReportError> {
        match self {
            Self::Html(output) => {
                output.push_str("<dt>")?;
                write_html_text(output, label)?;
                output.push_str("</dt><dd>")
            },
            Self::Markdown(output) => output.push_fmt(format_args!("- {label}: ")),
        }
    }

    fn end_field(&mut self) -> Result<(), ReportError> {
        match self {
            Self::Html(output) => output.push_str("</dd>"),
            Self::Markdown(output) => output.push_char('\n'),
        }
    }

    fn begin_list_field(&mut self, label: &'static str) -> Result<(), ReportError> {
        match self {
            Self::Html(output) => {
                output.push_str("<dt>")?;
                write_html_text(output, label)?;
                output.push_str("</dt><dd><ul>")
            },
            Self::Markdown(output) => output.push_fmt(format_args!("- {label}:\n")),
        }
    }

    fn begin_list_item(&mut self) -> Result<(), ReportError> {
        match self {
            Self::Html(output) => output.push_str("<li>"),
            Self::Markdown(output) => output.push_str("  - "),
        }
    }

    fn end_list_item(&mut self) -> Result<(), ReportError> {
        match self {
            Self::Html(output) => output.push_str("</li>"),
            Self::Markdown(output) => output.push_char('\n'),
        }
    }

    fn end_list_field(&mut self) -> Result<(), ReportError> {
        match self {
            Self::Html(output) => output.push_str("</ul></dd>"),
            Self::Markdown(_) => Ok(()),
        }
    }

    fn begin_record(&mut self) -> Result<(), ReportError> {
        match self {
            Self::Html(output) => output.push_str("<details class=\"wp-detail\" open><summary>"),
            Self::Markdown(output) => output.push_str("#### "),
        }
    }

    fn end_record_title(&mut self) -> Result<(), ReportError> {
        match self {
            Self::Html(output) => output.push_str("</summary><dl>"),
            Self::Markdown(output) => output.push_str("\n\n"),
        }
    }

    fn end_record(&mut self) -> Result<(), ReportError> {
        match self {
            Self::Html(output) => output.push_str("</dl></details>"),
            Self::Markdown(output) => output.push_char('\n'),
        }
    }

    fn empty(&mut self, text: &'static str) -> Result<(), ReportError> {
        match self {
            Self::Html(output) => {
                output.push_str("<p class=\"empty\">")?;
                write_html_text(output, text)?;
                output.push_str("</p>")
            },
            Self::Markdown(output) => {
                output.push_str(text)?;
                output.push_char('\n')
            },
        }
    }
}
#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
fn write_html_wordpress_external_attribution(
    output: &mut RenderBuffer,
    audit: &AssessmentWordPressAuditDocument,
) -> Result<(), ReportError> {
    let Some(external) = &audit.external_review else {
        return Ok(());
    };
    output.push_str("<h3>External source attribution</h3><ul>")?;
    for evaluation in &external.evaluations {
        let Some(reference) = &evaluation.record_reference else {
            continue;
        };
        output.push_str("<li><code>")?;
        write_html_text(output, &evaluation.key.upstream_id)?;
        output.push_str("</code> <a rel=\"noreferrer noopener\" href=\"")?;
        write_html_text(output, reference)?;
        output.push_str("\">Selected source reference</a></li>")?;
    }
    output.push_str("</ul><h3>Rights notices</h3><ul>")?;
    for notice in &external.notices {
        output.push_str("<li><strong>Party:</strong> <code>")?;
        write_html_text(output, &notice.party)?;
        output.push_str("</code><br><strong>Message:</strong> <code>")?;
        write_html_text(output, &notice.message)?;
        output.push_str("</code><br><strong>Notice:</strong> <code>")?;
        write_html_text(output, &notice.notice)?;
        output.push_str("</code><br><strong>License:</strong> <code>")?;
        write_html_text(output, &notice.license)?;
        output.push_str("</code>")?;
        if is_strict_https_reference(&notice.license_url) {
            output.push_str(" <a rel=\"noreferrer noopener\" href=\"")?;
            write_html_text(output, &notice.license_url)?;
            output.push_str("\">License terms</a>")?;
        } else {
            output.push_str("<br><strong>License URL:</strong> <code>")?;
            write_html_text(output, &notice.license_url)?;
            output.push_str("</code>")?;
        }
        output.push_str("</li>")?;
    }
    output.push_str("</ul>")
}

#[cfg(feature = "scanning")]
fn render_assessment_markdown(
    document: &AssessmentDocument<'_>,
    limit: usize,
) -> Result<String, ReportError> {
    let mut output = RenderBuffer::new(limit);
    output.push_str("# Termivar assessment report\n\n")?;
    for (label, value) in document.metadata() {
        output.push_fmt(format_args!("- {label}: "))?;
        write_markdown_code_span(&mut output, &value)?;
        output.push_char('\n')?;
    }
    #[cfg(feature = "authorization-review")]
    if let Some(audit) = &document.authorization_review {
        output.push_str("\n## Resource authorization review audit\n\n")?;
        for (label, value) in audit.metadata() {
            output.push_fmt(format_args!("- {label}: "))?;
            write_markdown_code_span(&mut output, &value)?;
            output.push_char('\n')?;
        }
    }
    #[cfg(feature = "openapi-review")]
    if let Some(audit) = &document.openapi_review {
        output.push_str("\n## OpenAPI review audit\n\n")?;
        for (label, value) in audit.metadata() {
            output.push_fmt(format_args!("- {label}: "))?;
            write_markdown_code_span(&mut output, &value)?;
            output.push_char('\n')?;
        }
    }
    #[cfg(feature = "rest-review")]
    if let Some(audit) = &document.rest_review {
        output.push_str("\n## REST read-only review audit\n\n")?;
        for (label, value) in audit.metadata() {
            output.push_fmt(format_args!("- {label}: "))?;
            write_markdown_code_span(&mut output, &value)?;
            output.push_char('\n')?;
        }
    }
    #[cfg(feature = "wordpress-review")]
    if let Some(audit) = &document.wordpress_review {
        output.push_str("\n## WordPress evidence review audit\n\n")?;
        for (label, value) in audit.metadata() {
            output.push_fmt(format_args!("- {label}: "))?;
            write_markdown_code_span(&mut output, &value)?;
            output.push_char('\n')?;
        }
        write_wordpress_presentation(
            &mut WordPressPresentationEmitter::Markdown(&mut output),
            audit,
        )?;
        write_markdown_wordpress_external_attribution(&mut output, audit)?;
    }
    #[cfg(feature = "wordpress-review")]
    if let Some(discovery) = &document.wordpress_discovery {
        output.push_str("\n## WordPress public metadata discovery audit\n\n")?;
        for (label, value) in discovery.metadata() {
            output.push_fmt(format_args!("- {label}: "))?;
            write_markdown_code_span(&mut output, &value)?;
            output.push_char('\n')?;
        }
        write_wordpress_discovery_presentation(
            &mut WordPressPresentationEmitter::Markdown(&mut output),
            discovery,
        )?;
    }
    output.push_str("\n## Assessment items\n\n")?;
    if document.items.is_empty() {
        output.push_str("No assessment items.\n")?;
    } else {
        for (index, item) in document.items.iter().enumerate() {
            output.push_fmt(format_args!("### Item {}\n\n- Disposition: ", index + 1))?;
            write_markdown_code_span(&mut output, item.disposition)?;
            for (label, value) in item.required_metadata() {
                output.push_fmt(format_args!("\n- {label}: "))?;
                write_markdown_code_span(&mut output, &value)?;
            }
            output.push_str("\n- Severity: ")?;
            write_markdown_optional_assessment_text(&mut output, item.severity, "not assigned")?;
            output.push_str("\n- CWE: ")?;
            write_markdown_optional_assessment_text(&mut output, item.cwe, "not applicable")?;
            output.push_str("\n\n")?;
        }
    }
    Ok(output.finish())
}

#[cfg(feature = "scanning")]
fn write_markdown_optional_assessment_text(
    output: &mut RenderBuffer,
    value: Option<&str>,
    absent: &'static str,
) -> Result<(), ReportError> {
    write_markdown_code_span(output, value.unwrap_or(absent))
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
fn write_markdown_wordpress_external_attribution(
    output: &mut RenderBuffer,
    audit: &AssessmentWordPressAuditDocument,
) -> Result<(), ReportError> {
    let Some(external) = &audit.external_review else {
        return Ok(());
    };
    output.push_str("\n### External source attribution\n\n")?;
    for evaluation in &external.evaluations {
        let Some(reference) = &evaluation.record_reference else {
            continue;
        };
        output.push_str("- Record ")?;
        write_markdown_code_span(output, &evaluation.key.upstream_id)?;
        output.push_str(": [Selected source reference](<")?;
        output.push_str(reference)?;
        output.push_str(">)\n")?;
    }
    output.push_str("\n#### Rights notices\n\n")?;
    for notice in &external.notices {
        output.push_str("- Party: ")?;
        write_markdown_code_span(output, &notice.party)?;
        output.push_str("; message: ")?;
        write_markdown_code_span(output, &notice.message)?;
        output.push_str("; notice: ")?;
        write_markdown_code_span(output, &notice.notice)?;
        output.push_str("; license: ")?;
        write_markdown_code_span(output, &notice.license)?;
        if is_strict_https_reference(&notice.license_url) {
            output.push_str("; [License terms](<")?;
            output.push_str(&notice.license_url)?;
            output.push_str(">)")?;
        } else {
            output.push_str("; license URL: ")?;
            write_markdown_code_span(output, &notice.license_url)?;
        }
        output.push_char('\n')?;
    }
    Ok(())
}

#[cfg(feature = "scanning")]
#[derive(Serialize)]
struct AssessmentDocument<'a> {
    schema: &'static str,
    source_schema: &'a str,
    run_schema: &'a str,
    profile_schema: &'a str,
    profile: &'a str,
    status: &'static str,
    subject_count: u64,
    item_count: u64,
    #[cfg(feature = "authorization-review")]
    #[serde(skip_serializing_if = "Option::is_none")]
    authorization_review: Option<AssessmentAuthorizationAuditDocument>,
    #[cfg(feature = "openapi-review")]
    #[serde(skip_serializing_if = "Option::is_none")]
    openapi_review: Option<AssessmentOpenApiAuditDocument>,
    #[cfg(feature = "rest-review")]
    #[serde(skip_serializing_if = "Option::is_none")]
    rest_review: Option<AssessmentRestAuditDocument>,
    #[cfg(feature = "wordpress-review")]
    #[serde(skip_serializing_if = "Option::is_none")]
    wordpress_review: Option<AssessmentWordPressAuditDocument>,
    #[cfg(feature = "wordpress-review")]
    #[serde(skip_serializing_if = "Option::is_none")]
    wordpress_discovery: Option<AssessmentWordPressDiscoveryAuditDocument>,
    items: Vec<AssessmentItemDocument<'a>>,
}

#[cfg(feature = "scanning")]
impl<'a> AssessmentDocument<'a> {
    fn from_report(report: &'a AssessmentRunReport) -> Result<Self, ReportError> {
        let items = report
            .items()
            .iter()
            .map(AssessmentItemDocument::from_item)
            .collect::<Result<Vec<_>, _>>()?;
        #[cfg(feature = "wordpress-review")]
        let wordpress_discovery = {
            let discovery_evidence_references = items
                .iter()
                .find(|item| item.capability_id == WORDPRESS_DISCOVERY_OBSERVATION_CAPABILITY_ID)
                .map_or(&[][..], |item| item.evidence_references.as_slice());
            match report.wordpress_review_audit() {
                Some(audit) => AssessmentWordPressDiscoveryAuditDocument::from_wordpress_audit(
                    audit,
                    discovery_evidence_references,
                )?,
                None => None,
            }
        };
        Ok(Self {
            schema: ASSESSMENT_REPORT_DOCUMENT_SCHEMA,
            source_schema: report.schema(),
            run_schema: report.run_report().schema(),
            profile_schema: report.profile().schema(),
            profile: report.profile().profile().id(),
            status: run_status_token(report.run_report().status()),
            subject_count: u64::try_from(report.subject_count())
                .map_err(|_| ReportError::Serialization)?,
            item_count: u64::try_from(report.item_count())
                .map_err(|_| ReportError::Serialization)?,
            #[cfg(feature = "authorization-review")]
            authorization_review: report
                .authorization_review_audit()
                .map(AssessmentAuthorizationAuditDocument::from_audit),
            #[cfg(feature = "openapi-review")]
            openapi_review: report
                .openapi_review_audit()
                .map(AssessmentOpenApiAuditDocument::from_audit),
            #[cfg(feature = "rest-review")]
            rest_review: report
                .rest_review_audit()
                .map(AssessmentRestAuditDocument::from_audit),
            #[cfg(feature = "wordpress-review")]
            wordpress_review: report
                .wordpress_review_audit()
                .map(AssessmentWordPressAuditDocument::from_audit),
            #[cfg(feature = "wordpress-review")]
            wordpress_discovery,
            items,
        })
    }

    fn metadata(&self) -> [(&'static str, String); 8] {
        [
            ("Schema", self.schema.to_owned()),
            ("Source schema", self.source_schema.to_owned()),
            ("Run schema", self.run_schema.to_owned()),
            ("Profile schema", self.profile_schema.to_owned()),
            ("Profile", self.profile.to_owned()),
            ("Status", self.status.to_owned()),
            ("Subject count", self.subject_count.to_string()),
            ("Item count", self.item_count.to_string()),
        ]
    }

    fn validate(&self) -> Result<(), ReportError> {
        if self.schema != ASSESSMENT_REPORT_DOCUMENT_SCHEMA
            || self.item_count
                != u64::try_from(self.items.len()).map_err(|_| ReportError::Serialization)?
        {
            return Err(ReportError::Serialization);
        }
        #[cfg(feature = "authorization-review")]
        if let Some(audit) = &self.authorization_review {
            audit.validate(&self.items)?;
        }
        #[cfg(feature = "openapi-review")]
        if let Some(audit) = &self.openapi_review {
            audit.validate(&self.items)?;
        }
        #[cfg(feature = "rest-review")]
        if let Some(audit) = &self.rest_review {
            audit.validate(&self.items)?;
        } else if self
            .items
            .iter()
            .any(|item| item.capability_id == REST_REVIEW_CAPABILITY_ID)
        {
            return Err(ReportError::Serialization);
        }
        #[cfg(feature = "wordpress-review")]
        if let Some(audit) = &self.wordpress_review {
            audit.validate(&self.items)?;
        } else if self
            .items
            .iter()
            .any(|item| item.capability_id == WORDPRESS_REVIEW_CAPABILITY_ID)
        {
            return Err(ReportError::Serialization);
        }
        #[cfg(feature = "wordpress-review")]
        let discovery_items = self
            .items
            .iter()
            .filter(|item| item.capability_id == WORDPRESS_DISCOVERY_OBSERVATION_CAPABILITY_ID)
            .collect::<Vec<_>>();
        #[cfg(feature = "wordpress-review")]
        match (&self.wordpress_review, &self.wordpress_discovery) {
            (Some(review), Some(discovery)) => {
                discovery.validate()?;
                if review.schema != "security.wordpress-review-audit/v7"
                    || review.additional_request_count != discovery.attempted_request_count
                    || !wordpress_discovery_matches_review(review, discovery)
                    || (discovery_items.len() == 1) != (discovery.committed_response_count > 0)
                    || discovery_items.first().is_some_and(|item| {
                        item.evidence_count != u64::from(discovery.committed_response_count)
                            || item.evidence_references
                                != discovery
                                    .sources
                                    .iter()
                                    .flat_map(|source| source.evidence_references.iter())
                                    .cloned()
                                    .collect::<Vec<_>>()
                    })
                {
                    return Err(ReportError::Serialization);
                }
            },
            (Some(review), None) if review.schema == "security.wordpress-review-audit/v7" => {
                return Err(ReportError::Serialization);
            },
            (None, Some(_)) => return Err(ReportError::Serialization),
            _ if !discovery_items.is_empty() => return Err(ReportError::Serialization),
            _ => {},
        }
        for item in &self.items {
            item.validate()?;
        }
        Ok(())
    }
}

#[cfg(all(feature = "scanning", feature = "openapi-review"))]
#[derive(Serialize)]
struct AssessmentOpenApiAuditDocument {
    schema: &'static str,
    capability_id: &'static str,
    outcome: &'static str,
    candidate_source: crate::web_runtime::OpenApiCandidateSource,
    request_count: u8,
    active_verification_count: u8,
    version: Option<&'static str>,
    semantic_digest: Option<String>,
    path_count: u32,
    operation_count: u32,
    get_operation_count: u32,
    write_operation_count: u32,
    path_parameter_count: u32,
    query_parameter_count: u32,
    explicit_auth_operation_count: u32,
    anonymous_operation_count: u32,
    url_like_operation_count: u32,
    multipart_operation_count: u32,
    deprecated_operation_count: u32,
    replay_matched: bool,
    item_projected: bool,
}
#[cfg(all(feature = "scanning", feature = "openapi-review"))]
impl AssessmentOpenApiAuditDocument {
    fn from_audit(a: &crate::web_runtime::WebAssessmentOpenApiAudit) -> Self {
        Self {
            schema: "security.openapi-review-audit/v1",
            capability_id: OPENAPI_REVIEW_CAPABILITY_ID,
            outcome: openapi_outcome(a.outcome()),
            candidate_source: a.candidate_source(),
            request_count: a.request_count(),
            active_verification_count: a.active_verification_count(),
            version: a.version(),
            semantic_digest: a.semantic_digest().map(str::to_owned),
            path_count: a.path_count(),
            operation_count: a.operation_count(),
            get_operation_count: a.get_operation_count(),
            write_operation_count: a.write_operation_count(),
            path_parameter_count: a.path_parameter_count(),
            query_parameter_count: a.query_parameter_count(),
            explicit_auth_operation_count: a.explicit_auth_operation_count(),
            anonymous_operation_count: a.anonymous_operation_count(),
            url_like_operation_count: a.url_like_operation_count(),
            multipart_operation_count: a.multipart_operation_count(),
            deprecated_operation_count: a.deprecated_operation_count(),
            replay_matched: a.replay_matched(),
            item_projected: a.item_projected(),
        }
    }
    fn validate(&self, items: &[AssessmentItemDocument<'_>]) -> Result<(), ReportError> {
        let count = items
            .iter()
            .filter(|i| i.capability_id == OPENAPI_REVIEW_CAPABILITY_ID)
            .count();
        if self.request_count > 2
            || self.active_verification_count > 1
            || count > 1
            || self.item_projected != (count == 1)
            || self.replay_matched != self.item_projected
        {
            return Err(ReportError::Serialization);
        }
        Ok(())
    }
    fn summary(&self) -> String {
        format!("source={};version={};digest={};paths={};operations={};get={};write={};path_parameters={};query_parameters={};explicit_auth={};anonymous={};url_like={};multipart={};deprecated={};replay_matched={};item_projected={}",self.candidate_source.as_str(),self.version.unwrap_or("none"),self.semantic_digest.as_deref().unwrap_or("none"),self.path_count,self.operation_count,self.get_operation_count,self.write_operation_count,self.path_parameter_count,self.query_parameter_count,self.explicit_auth_operation_count,self.anonymous_operation_count,self.url_like_operation_count,self.multipart_operation_count,self.deprecated_operation_count,self.replay_matched,self.item_projected)
    }
    fn metadata(&self) -> Vec<(&'static str, String)> {
        vec![
            ("Audit schema", self.schema.into()),
            ("Capability", self.capability_id.into()),
            ("Outcome", self.outcome.into()),
            ("Request count", self.request_count.to_string()),
            (
                "Active verification count",
                self.active_verification_count.to_string(),
            ),
            ("Summary", self.summary()),
        ]
    }
}
#[cfg(all(feature = "scanning", feature = "openapi-review"))]
const fn openapi_outcome(o: OpenApiRuntimeOutcome) -> &'static str {
    match o {
        OpenApiRuntimeOutcome::NotEligible => "not_eligible",
        OpenApiRuntimeOutcome::DocumentObserved => "document_observed",
        OpenApiRuntimeOutcome::Swagger20MetadataOnly => "swagger_20_metadata_only",
        OpenApiRuntimeOutcome::UnsupportedVersion => "unsupported_version",
        OpenApiRuntimeOutcome::ReplayMismatch => "replay_mismatch",
        OpenApiRuntimeOutcome::UnsupportedMedia => "unsupported_media",
        OpenApiRuntimeOutcome::Malformed => "malformed",
        OpenApiRuntimeOutcome::LimitExceeded => "limit_exceeded",
        OpenApiRuntimeOutcome::TooLarge => "too_large",
        OpenApiRuntimeOutcome::RedirectObserved => "redirect_observed",
        OpenApiRuntimeOutcome::RateLimited => "rate_limited",
        OpenApiRuntimeOutcome::DefensiveInterference => "defensive_interference",
        OpenApiRuntimeOutcome::HttpError => "http_error",
        OpenApiRuntimeOutcome::Truncated => "truncated",
        OpenApiRuntimeOutcome::Incomplete => "incomplete",
        OpenApiRuntimeOutcome::BudgetExhausted => "budget_exhausted",
        OpenApiRuntimeOutcome::Cancelled => "cancelled",
    }
}

#[cfg(all(feature = "scanning", feature = "rest-review"))]
#[derive(Serialize)]
struct AssessmentRestAuditDocument {
    schema: &'static str,
    capability_id: &'static str,
    enabled: bool,
    method: &'static str,
    outcome: &'static str,
    request_count: u8,
    active_verification_count: u8,
    eligible_operation_count: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    selected_operation_identity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    documented_response: Option<&'static str>,
    observed_media: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    status_class: Option<u8>,
    replay_stable: bool,
    item_projected: bool,
}

#[cfg(all(feature = "scanning", feature = "rest-review"))]
impl AssessmentRestAuditDocument {
    fn from_audit(audit: &crate::web_runtime::WebAssessmentRestAudit) -> Self {
        Self {
            schema: "security.rest-readonly-review-audit/v1",
            capability_id: REST_REVIEW_CAPABILITY_ID,
            enabled: true,
            method: "get",
            outcome: rest_outcome(audit.outcome()),
            request_count: audit.request_count(),
            active_verification_count: audit.active_verification_count(),
            eligible_operation_count: audit.eligible_operation_count(),
            selected_operation_identity: audit.selected_operation_identity().map(str::to_owned),
            documented_response: audit.documented_response().map(rest_documented_response),
            observed_media: rest_observed_media(audit.observed_media()),
            status_class: audit.status_class(),
            replay_stable: audit.replay_stable(),
            item_projected: audit.item_projected(),
        }
    }

    fn validate(&self, items: &[AssessmentItemDocument<'_>]) -> Result<(), ReportError> {
        let projected = items
            .iter()
            .filter(|item| item.capability_id == REST_REVIEW_CAPABILITY_ID)
            .count();
        let positive = self.outcome == "surface_observed";
        let selected_identity_is_valid = self
            .selected_operation_identity
            .as_deref()
            .is_none_or(|identity| identity.starts_with("openapi-operation-sha256:"));
        if self.schema != "security.rest-readonly-review-audit/v1"
            || self.capability_id != REST_REVIEW_CAPABILITY_ID
            || !self.enabled
            || self.method != "get"
            || usize::from(self.request_count) > MAX_REST_REVIEW_REQUESTS
            || usize::from(self.active_verification_count) > MAX_REST_REVIEW_ACTIVE_VERIFICATIONS
            || usize::from(self.active_verification_count)
                != usize::from(usize::from(self.request_count) == MAX_REST_REVIEW_REQUESTS)
            || projected > 1
            || self.item_projected != (projected == 1)
            || positive != self.item_projected
            || self.replay_stable != positive
            || !selected_identity_is_valid
            || (positive
                && (usize::from(self.request_count) != MAX_REST_REVIEW_REQUESTS
                    || usize::from(self.active_verification_count)
                        != MAX_REST_REVIEW_ACTIVE_VERIFICATIONS
                    || self.eligible_operation_count == 0
                    || self.selected_operation_identity.is_none()))
        {
            return Err(ReportError::Serialization);
        }
        Ok(())
    }

    fn summary(&self) -> String {
        format!(
            "enabled={};method={};eligible_operations={};selected_operation={};documented_response={};observed_media={};status_class={};replay_stable={};item_projected={}",
            self.enabled,
            self.method,
            self.eligible_operation_count,
            self.selected_operation_identity.as_deref().unwrap_or("none"),
            self.documented_response.unwrap_or("none"),
            self.observed_media,
            self.status_class
                .map_or_else(|| "none".to_owned(), |status| status.to_string()),
            self.replay_stable,
            self.item_projected,
        )
    }

    fn metadata(&self) -> Vec<(&'static str, String)> {
        vec![
            ("Audit schema", self.schema.into()),
            ("Capability", self.capability_id.into()),
            ("Enabled", self.enabled.to_string()),
            ("Method", self.method.into()),
            ("Outcome", self.outcome.into()),
            ("Request count", self.request_count.to_string()),
            (
                "Active verification count",
                self.active_verification_count.to_string(),
            ),
            ("Summary", self.summary()),
        ]
    }
}

#[cfg(all(feature = "scanning", feature = "rest-review"))]
const fn rest_documented_response(response: RestDocumentedResponseClass) -> &'static str {
    match response {
        RestDocumentedResponseClass::JsonCompatible => "json_compatible",
        RestDocumentedResponseClass::Unknown => "unknown",
    }
}

#[cfg(all(feature = "scanning", feature = "rest-review"))]
const fn rest_observed_media(media: RestObservedMediaClass) -> &'static str {
    match media {
        RestObservedMediaClass::JsonCompatible => "json_compatible",
        RestObservedMediaClass::Text => "text",
        RestObservedMediaClass::Unsupported => "unsupported",
        RestObservedMediaClass::Unknown => "unknown",
    }
}

#[cfg(all(feature = "scanning", feature = "rest-review"))]
const fn rest_outcome(outcome: RestRuntimeOutcome) -> &'static str {
    match outcome {
        RestRuntimeOutcome::NotEligible => "not_eligible",
        RestRuntimeOutcome::SurfaceObserved => "surface_observed",
        RestRuntimeOutcome::ReplayMismatch => "replay_mismatch",
        RestRuntimeOutcome::CompleteNonJson => "complete_non_json",
        RestRuntimeOutcome::Redirect => "redirect",
        RestRuntimeOutcome::AuthenticationRequired => "authentication_required",
        RestRuntimeOutcome::Forbidden => "forbidden",
        RestRuntimeOutcome::NotFound => "not_found",
        RestRuntimeOutcome::RateLimited => "rate_limited",
        RestRuntimeOutcome::DefensiveInterference => "defensive_interference",
        RestRuntimeOutcome::ServerError => "server_error",
        RestRuntimeOutcome::UnsupportedMedia => "unsupported_media",
        RestRuntimeOutcome::Truncated => "truncated",
        RestRuntimeOutcome::Incomplete => "incomplete",
        RestRuntimeOutcome::Cancelled => "cancelled",
        RestRuntimeOutcome::BudgetExhausted => "budget_exhausted",
    }
}

#[cfg(all(feature = "scanning", feature = "authorization-review"))]
#[derive(Serialize)]
struct AssessmentAuthorizationAuditDocument {
    schema: &'static str,
    capability_id: &'static str,
    policy_id: String,
    selected_path_count: u8,
    ignored_path_count: u8,
    request_count: u8,
    outcome: &'static str,
    primary_stable: Option<bool>,
    peer_stable: Option<bool>,
    cross_resources_equivalent: Option<bool>,
    item_projected: bool,
}

#[cfg(all(feature = "scanning", feature = "authorization-review"))]
impl AssessmentAuthorizationAuditDocument {
    fn from_audit(audit: &crate::web_runtime::WebAssessmentAuthorizationAudit) -> Self {
        Self {
            schema: "security.authorization-review-audit/v1",
            capability_id: RESOURCE_AUTHORIZATION_REVIEW_CAPABILITY_ID,
            policy_id: audit.policy_id().to_string(),
            selected_path_count: audit.selected_path_count(),
            ignored_path_count: audit.ignored_path_count(),
            request_count: audit.request_count(),
            outcome: authorization_review_outcome_token(audit.outcome()),
            primary_stable: audit.primary_stable(),
            peer_stable: audit.peer_stable(),
            cross_resources_equivalent: audit.cross_resources_equivalent(),
            item_projected: audit.item_projected(),
        }
    }

    fn validate(&self, items: &[AssessmentItemDocument<'_>]) -> Result<(), ReportError> {
        let projected_count = items
            .iter()
            .filter(|item| item.capability_id == RESOURCE_AUTHORIZATION_REVIEW_CAPABILITY_ID)
            .count();
        let positive = self.outcome == "stable_cross_principal_equivalence";
        if self.schema != "security.authorization-review-audit/v1"
            || self.capability_id != RESOURCE_AUTHORIZATION_REVIEW_CAPABILITY_ID
            || !self.policy_id.starts_with("authorization-policy-sha256:")
            || self.selected_path_count == 0
            || usize::from(self.selected_path_count) > HARD_MAX_AUTHORIZATION_REVIEW_SELECTED_PATHS
            || usize::from(self.ignored_path_count) > HARD_MAX_AUTHORIZATION_REVIEW_IGNORED_PATHS
            || usize::from(self.request_count) > MAX_AUTHORIZATION_REVIEW_REQUESTS
            || projected_count > 1
            || self.item_projected != (projected_count == 1)
            || positive != self.item_projected
            || (positive && usize::from(self.request_count) != MAX_AUTHORIZATION_REVIEW_REQUESTS)
        {
            return Err(ReportError::Serialization);
        }
        Ok(())
    }

    fn metadata(&self) -> [(&'static str, String); 11] {
        [
            ("Audit schema", self.schema.to_owned()),
            ("Capability", self.capability_id.to_owned()),
            ("Policy ID", self.policy_id.clone()),
            ("Selected path count", self.selected_path_count.to_string()),
            ("Ignored path count", self.ignored_path_count.to_string()),
            ("Request count", self.request_count.to_string()),
            ("Outcome", self.outcome.to_owned()),
            ("Primary stable", optional_bool_token(self.primary_stable)),
            ("Peer stable", optional_bool_token(self.peer_stable)),
            (
                "Cross resources equivalent",
                optional_bool_token(self.cross_resources_equivalent),
            ),
            ("Item projected", self.item_projected.to_string()),
        ]
    }
}

#[cfg(all(feature = "scanning", feature = "authorization-review"))]
fn optional_bool_token(value: Option<bool>) -> String {
    match value {
        Some(true) => "true".to_owned(),
        Some(false) => "false".to_owned(),
        None => "not available".to_owned(),
    }
}

#[cfg(all(feature = "scanning", feature = "authorization-review"))]
const fn authorization_review_outcome_token(outcome: AuthorizationReviewOutcome) -> &'static str {
    match outcome {
        AuthorizationReviewOutcome::NotEligible => "not_eligible",
        AuthorizationReviewOutcome::PrimaryBaselineInvalid => "primary_baseline_invalid",
        AuthorizationReviewOutcome::PrimaryUnstable => "primary_unstable",
        AuthorizationReviewOutcome::PeerDenied => "peer_denied",
        AuthorizationReviewOutcome::PeerUnstable => "peer_unstable",
        AuthorizationReviewOutcome::CrossStatusDifferent => "cross_status_different",
        AuthorizationReviewOutcome::CrossFieldsEquivalentOnly => "cross_fields_equivalent_only",
        AuthorizationReviewOutcome::CrossResourcesDifferent => "cross_resources_different",
        AuthorizationReviewOutcome::StableCrossPrincipalEquivalence => {
            "stable_cross_principal_equivalence"
        },
        AuthorizationReviewOutcome::DefensiveInterference => "defensive_interference",
        AuthorizationReviewOutcome::RateLimited => "rate_limited",
        AuthorizationReviewOutcome::RedirectObserved => "redirect_observed",
        AuthorizationReviewOutcome::UnsupportedMedia => "unsupported_media",
        AuthorizationReviewOutcome::MalformedJson => "malformed_json",
        AuthorizationReviewOutcome::GenericJsonErrorEnvelope => "generic_json_error_envelope",
        AuthorizationReviewOutcome::SelectedPathMissing => "selected_path_missing",
        AuthorizationReviewOutcome::Truncated => "truncated",
        AuthorizationReviewOutcome::Incomplete => "incomplete",
        AuthorizationReviewOutcome::BudgetExhausted => "budget_exhausted",
        AuthorizationReviewOutcome::Cancelled => "cancelled",
        AuthorizationReviewOutcome::ContractMismatch => "contract_mismatch",
    }
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
#[derive(Serialize)]
struct AssessmentWordPressAuditDocument {
    schema: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    review_basis_schema: Option<&'static str>,
    capability_id: &'static str,
    catalog_status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    catalog_schema: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    catalog: Option<WordPressCatalogDocument>,
    #[serde(skip_serializing_if = "Option::is_none")]
    inventory_import: Option<WordPressInventoryImportDocument>,
    #[serde(skip_serializing_if = "Option::is_none")]
    external_review: Option<WordPressExternalReviewDocument>,
    signal_count: u16,
    evidence_reference_count: u16,
    additional_request_count: u8,
    item_projected: bool,
    component_count: usize,
    advisory_count: usize,
    components: Vec<WordPressComponentDocument>,
    advisories: Vec<WordPressAdvisoryDocument>,
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
const WORDPRESS_DISCOVERY_AUDIT_SCHEMA: &str = "security.wordpress-discovery-audit/v1";
#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
const WORDPRESS_DISCOVERY_POLICY_ID: &str = "termivar.wordpress-metadata-discovery/v1";
#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
const WORDPRESS_DISCOVERY_CAPABILITY_ID: &str = "technology.wordpress-metadata-discovery@1";
#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
const MAX_WORDPRESS_DISCOVERY_AUDIT_SOURCES: usize = 32;
#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
const MAX_WORDPRESS_DISCOVERY_AUDIT_REQUESTS: u8 = 12;
#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
const MAX_WORDPRESS_DISCOVERY_AUDIT_REST_REQUESTS: usize = 1;
#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
const MAX_WORDPRESS_DISCOVERY_AUDIT_THEME_REQUESTS: usize = 3;
#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
const MAX_WORDPRESS_DISCOVERY_AUDIT_PLUGIN_REQUESTS: usize = 8;
#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
const MAX_WORDPRESS_DISCOVERY_AUDIT_OMITTED_CANDIDATES: u64 = 4_064;
#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
const MAX_WORDPRESS_DISCOVERY_AUDIT_METADATA_BYTES: usize = 256;
#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
const MAX_WORDPRESS_DISCOVERY_AUDIT_VERSION_BYTES: usize = 64;
#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
const MAX_WORDPRESS_DISCOVERY_AUDIT_NAMESPACE_BYTES: usize = 128;
#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
const MAX_WORDPRESS_DISCOVERY_AUDIT_NAMESPACES: usize = 64;
/// Separate optional wire audit for explicitly selected metadata collection.
///
/// Collection details remain separate from the versioned WordPress review
/// result. A discovery-influenced review uses audit v7 so the vocabulary and
/// request accounting of previously published v1-v6 documents stay unchanged.
#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
#[derive(Serialize)]
struct AssessmentWordPressDiscoveryAuditDocument {
    schema: &'static str,
    capability_id: &'static str,
    policy_id: &'static str,
    selected: bool,
    method: &'static str,
    credential_mode: &'static str,
    seed_count: u8,
    candidate_count: u8,
    candidate_limit_reached: bool,
    omitted_candidate_count: u64,
    attempted_request_count: u8,
    completed_response_count: u8,
    committed_response_count: u8,
    response_bytes: u64,
    source_count: usize,
    sources: Vec<WordPressDiscoverySourceDocument>,
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
#[derive(Serialize)]
struct WordPressDiscoverySourceDocument {
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    component: Option<WordPressComponentIdentityDocument>,
    parent_depth: u8,
    outcome: &'static str,
    request_attempted: bool,
    response_bytes: u64,
    evidence_reference_count: usize,
    evidence_references: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    namespaces: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    theme: Option<WordPressThemeDiscoveryDocument>,
    #[serde(skip_serializing_if = "Option::is_none")]
    plugin: Option<WordPressPluginDiscoveryDocument>,
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
#[derive(Serialize)]
struct WordPressThemeDiscoveryDocument {
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    template: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    requires_wordpress: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    requires_php: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tested_up_to: Option<String>,
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
#[derive(Serialize)]
struct WordPressPluginDiscoveryDocument {
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stable_tag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    requires_wordpress: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    requires_php: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tested_up_to: Option<String>,
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
#[derive(Serialize)]
struct WordPressCatalogDocument {
    id: String,
    revision: String,
    retrieved_on: String,
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
#[derive(Serialize)]
struct WordPressComponentIdentityDocument {
    kind: &'static str,
    slug: String,
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
#[derive(Serialize)]
struct WordPressComponentDocument {
    identity: WordPressComponentIdentityDocument,
    evidence_class: &'static str,
    identity_sources: Vec<&'static str>,
    confidence_classes: Vec<&'static str>,
    versions: Vec<WordPressVersionEvidenceDocument>,
    activation: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    inventory_status: Option<&'static str>,
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
#[derive(Serialize)]
struct WordPressInventoryImportDocument {
    coverage: WordPressInventoryCoverageDocument,
    component_count: usize,
    limitations: Vec<WordPressInventoryLimitationDocument>,
    inputs: Vec<WordPressInventoryInputDocument>,
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
#[derive(Serialize)]
struct WordPressInventoryCoverageDocument {
    core: &'static str,
    plugins: &'static str,
    themes: &'static str,
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
#[derive(Serialize)]
struct WordPressInventoryLimitationDocument {
    declared_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    status: &'static str,
    reason: &'static str,
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
#[derive(Serialize)]
struct WordPressInventoryInputDocument {
    class: &'static str,
    byte_length: usize,
    sha256: String,
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
#[derive(Serialize)]
struct WordPressExternalReviewDocument {
    source_namespace: &'static str,
    source_format: &'static str,
    mapping_revision: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    identity_mapping_policy: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    identity_source_assurance: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource_policy: Option<&'static str>,
    comparison_policy: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    comparison_profile: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_selection: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_semantics_assurance: Option<&'static str>,
    input: WordPressExternalInputDocument,
    counts: WordPressExternalCountsDocument,
    notices: Vec<WordPressExternalNoticeDocument>,
    evaluations: Vec<WordPressExternalEvaluationDocument>,
    #[serde(skip_serializing_if = "Option::is_none")]
    identity_limitations: Option<Vec<WordPressExternalIdentityLimitationDocument>>,
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
#[derive(Serialize)]
struct WordPressExternalInputDocument {
    byte_length: u64,
    sha256: String,
    semantic_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    accounted_retained_bytes: Option<usize>,
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
#[derive(Serialize)]
struct WordPressExternalCountsDocument {
    parsed_records: usize,
    software_associations: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    exact_identity_associations: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    candidate_identity_associations: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ambiguous_identity_associations: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    unresolved_identity_associations: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    projected_identity_limitations: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    unprojected_identity_limitations: Option<usize>,
    selected_associations: usize,
    evaluable_associations: usize,
    unsupported_associations: usize,
    excluded_associations: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    mapped_unselected_associations: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    within_associations: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    outside_associations: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    indeterminate_associations: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    selected_ranges: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    evaluated_ranges: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    containing_ranges: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    noncontaining_ranges: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    unsupported_ranges: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    invalid_ranges: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    not_evaluated_ranges: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    partial_range_coverage_associations: Option<usize>,
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
#[derive(Serialize)]
struct WordPressExternalNoticeDocument {
    id: String,
    message: String,
    party: String,
    notice: String,
    license: String,
    license_url: String,
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
#[derive(Serialize)]
struct WordPressExternalEvaluationDocument {
    key: WordPressExternalEvaluationKeyDocument,
    #[serde(skip_serializing_if = "Option::is_none")]
    identity_mapping: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    identity_collision_raw_count: Option<usize>,
    title: String,
    display_name: String,
    informational: bool,
    description: String,
    references: Vec<String>,
    record_reference: Option<String>,
    cwe: Option<WordPressExternalCweDocument>,
    cvss: Option<WordPressExternalCvssDocument>,
    cve: Option<String>,
    cve_link: Option<String>,
    researchers: Vec<String>,
    source_dates: WordPressExternalSourceDatesDocument,
    affected_ranges: Vec<WordPressExternalRangeDocument>,
    #[serde(skip_serializing_if = "Option::is_none")]
    range_evaluations: Option<Vec<WordPressExternalRangeEvaluationDocument>>,
    source_patched: bool,
    source_patched_versions: Vec<String>,
    source_remediation: String,
    notice_ids: Vec<String>,
    component_evidence: &'static str,
    version_evidence_resolution: WordPressExternalVersionEvidenceResolutionDocument,
    version_relation: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    version_relation_reason: Option<&'static str>,
    applicability: &'static str,
    execution: WordPressExternalExecutionDocument,
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
#[derive(Serialize)]
struct WordPressExternalIdentityLimitationDocument {
    key: WordPressExternalIdentityLimitationKeyDocument,
    identity_resolution: &'static str,
    title: String,
    display_name: String,
    references: Vec<String>,
    record_reference: Option<String>,
    affected_ranges: Vec<WordPressExternalRangeDocument>,
    range_evaluations: Vec<WordPressExternalRangeEvaluationDocument>,
    source_patched: bool,
    source_patched_versions: Vec<String>,
    source_remediation: String,
    notice_ids: Vec<String>,
    version_relation: &'static str,
    version_relation_reason: &'static str,
    applicability: &'static str,
    execution: WordPressExternalExecutionDocument,
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
#[derive(Serialize)]
struct WordPressExternalIdentityLimitationKeyDocument {
    source_namespace: &'static str,
    upstream_id: String,
    source_component: WordPressExternalSourceComponentIdentityDocument,
    source_association_fingerprint: String,
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
#[derive(Serialize)]
struct WordPressExternalVersionEvidenceResolutionDocument {
    status: &'static str,
    evidence_row_count: usize,
    distinct_spelling_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    semantic_status: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    semantic_reason: Option<&'static str>,
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
#[derive(Serialize)]
struct WordPressExternalRangeEvaluationDocument {
    relation: &'static str,
    reason: &'static str,
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
#[derive(Serialize)]
struct WordPressExternalEvaluationKeyDocument {
    source_namespace: String,
    upstream_id: String,
    component: WordPressComponentIdentityDocument,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_component: Option<WordPressExternalSourceComponentIdentityDocument>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_association_fingerprint: Option<String>,
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
#[derive(Serialize)]
struct WordPressExternalSourceComponentIdentityDocument {
    kind: &'static str,
    slug: String,
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
#[derive(Serialize)]
struct WordPressExternalCweDocument {
    id: u32,
    name: String,
    description: String,
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
#[derive(Serialize)]
struct WordPressExternalCvssDocument {
    vector: String,
    score: String,
    rating: &'static str,
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
#[derive(Serialize)]
struct WordPressExternalSourceDatesDocument {
    published: Option<String>,
    updated: Option<String>,
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
#[derive(Serialize)]
struct WordPressExternalRangeDocument {
    label: String,
    from_kind: &'static str,
    from_version: String,
    from_inclusive: bool,
    to_kind: &'static str,
    to_version: String,
    to_inclusive: bool,
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
#[derive(Serialize)]
struct WordPressExternalExecutionDocument {
    exploit_execution: &'static str,
    impact_validation: &'static str,
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
#[derive(Serialize)]
struct WordPressVersionEvidenceDocument {
    value: String,
    source: &'static str,
    confidence: &'static str,
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
#[derive(Serialize)]
struct WordPressAdvisoryDocument {
    id: String,
    component: WordPressComponentIdentityDocument,
    source: WordPressAdvisorySourceDocument,
    cve: Option<String>,
    summary: String,
    affected_ranges: Vec<WordPressAffectedRangeDocument>,
    fixed_versions: Vec<String>,
    prerequisites: Vec<WordPressPrerequisiteDocument>,
    remediation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    comparison_profile: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version_resolution: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version_resolution_reason: Option<&'static str>,
    component_evidence: &'static str,
    version_relation: &'static str,
    applicability: &'static str,
    exploit_execution: &'static str,
    impact_validation: &'static str,
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
#[derive(Serialize)]
struct WordPressAdvisorySourceDocument {
    reference: String,
    revision: String,
    retrieved_on: String,
    usage_basis: String,
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
#[derive(Serialize)]
struct WordPressAffectedRangeDocument {
    lower: Option<WordPressVersionEndpointDocument>,
    upper: Option<WordPressVersionEndpointDocument>,
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
#[derive(Serialize)]
struct WordPressVersionEndpointDocument {
    declared: String,
    inclusive: bool,
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
#[derive(Serialize)]
struct WordPressPrerequisiteDocument {
    kind: &'static str,
    expected: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    patch_id: Option<String>,
    outcome: &'static str,
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
#[derive(Clone, Copy, PartialEq, Eq)]
enum WordPressPresentationGroup {
    ReviewCandidate,
    Contradicted,
    Limitation,
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
struct WordPressPresentationCounts {
    review_candidates: usize,
    contradicted: usize,
    limitations: usize,
    source_guidance: usize,
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
impl AssessmentWordPressAuditDocument {
    fn from_audit(audit: &WebAssessmentWordPressAudit) -> Self {
        let result = audit.result();
        let profiled = result.catalog_schema() == Some(WordPressAdvisoryCatalogSchema::V2);
        let external_schema = result.external_review().is_some();
        let explicit_external_schema = result.external_review().is_some_and(|review| {
            review.comparison_policy()
                == WordPressExternalComparisonPolicy::TermivarWordfenceV3ExplicitInterpretationV1
        });
        let source_identity_external_schema = result
            .external_review()
            .is_some_and(crate::wordpress_review::WordPressExternalReview::requires_audit_v6);
        let inventory_import = result.inventory_summary().map(|summary| {
            let coverage = summary.coverage();
            WordPressInventoryImportDocument {
                coverage: WordPressInventoryCoverageDocument {
                    core: wordpress_inventory_category_status(coverage.core()),
                    plugins: wordpress_inventory_category_status(coverage.plugins()),
                    themes: wordpress_inventory_category_status(coverage.themes()),
                },
                component_count: summary.component_count(),
                limitations: summary
                    .limitations()
                    .iter()
                    .map(|limitation| WordPressInventoryLimitationDocument {
                        declared_name: limitation.declared_name().to_owned(),
                        version: limitation.version().map(str::to_owned),
                        status: wordpress_inventory_entry_status(limitation.status()),
                        reason: wordpress_inventory_limitation_reason(limitation.reason()),
                    })
                    .collect(),
                inputs: result
                    .local_input_provenance()
                    .iter()
                    .map(|input| WordPressInventoryInputDocument {
                        class: wordpress_local_input_class(input.class()),
                        byte_length: input.byte_length(),
                        sha256: lowercase_hex(input.sha256()),
                    })
                    .collect(),
            }
        });
        let inventory_schema = inventory_import.is_some();
        let catalog = result
            .catalog_metadata()
            .map(|metadata| WordPressCatalogDocument {
                id: metadata.id().to_owned(),
                revision: metadata.revision().to_owned(),
                retrieved_on: metadata.retrieved_on().to_owned(),
            });
        let components = result
            .components()
            .iter()
            .map(|component| WordPressComponentDocument {
                identity: wordpress_component_identity(component.identity()),
                evidence_class: wordpress_evidence_class(component.evidence_class()),
                identity_sources: component
                    .identity_sources()
                    .iter()
                    .copied()
                    .map(wordpress_evidence_source)
                    .collect(),
                confidence_classes: component
                    .confidence_classes()
                    .iter()
                    .copied()
                    .map(wordpress_confidence)
                    .collect(),
                versions: component
                    .versions()
                    .iter()
                    .map(|version| WordPressVersionEvidenceDocument {
                        value: version.value().to_owned(),
                        source: wordpress_evidence_source(version.source()),
                        confidence: wordpress_confidence(version.confidence()),
                    })
                    .collect(),
                activation: component.activation().map(wordpress_activation),
                inventory_status: component
                    .inventory_status()
                    .map(wordpress_inventory_entry_status),
            })
            .collect::<Vec<_>>();
        let external_review = result
            .external_review()
            .map(wordpress_external_review_document);
        let advisories = result
            .advisories()
            .iter()
            .map(|evaluation| {
                let record = evaluation.record();
                WordPressAdvisoryDocument {
                    id: record.id().to_owned(),
                    component: wordpress_component_identity(record.component()),
                    source: WordPressAdvisorySourceDocument {
                        reference: record.source().reference().to_owned(),
                        revision: record.source().revision().to_owned(),
                        retrieved_on: record.source().retrieved_on().to_owned(),
                        usage_basis: record.source().usage_basis().to_owned(),
                    },
                    cve: record.cve().map(str::to_owned),
                    summary: record.summary().to_owned(),
                    affected_ranges: if profiled {
                        record
                            .profiled_affected_ranges()
                            .iter()
                            .map(|range| WordPressAffectedRangeDocument {
                                lower: range.lower().map(|endpoint| {
                                    WordPressVersionEndpointDocument {
                                        declared: endpoint.declared().to_owned(),
                                        inclusive: endpoint.inclusive(),
                                    }
                                }),
                                upper: range.upper().map(|endpoint| {
                                    WordPressVersionEndpointDocument {
                                        declared: endpoint.declared().to_owned(),
                                        inclusive: endpoint.inclusive(),
                                    }
                                }),
                            })
                            .collect()
                    } else {
                        record
                            .affected_ranges()
                            .iter()
                            .map(|range| WordPressAffectedRangeDocument {
                                lower: range.lower().map(|endpoint| {
                                    WordPressVersionEndpointDocument {
                                        declared: endpoint.declared().to_owned(),
                                        inclusive: endpoint.inclusive(),
                                    }
                                }),
                                upper: range.upper().map(|endpoint| {
                                    WordPressVersionEndpointDocument {
                                        declared: endpoint.declared().to_owned(),
                                        inclusive: endpoint.inclusive(),
                                    }
                                }),
                            })
                            .collect()
                    },
                    fixed_versions: record.fixed_versions().to_vec(),
                    prerequisites: evaluation
                        .prerequisites()
                        .iter()
                        .map(|prerequisite| {
                            wordpress_prerequisite(
                                prerequisite.prerequisite(),
                                prerequisite.outcome(),
                            )
                        })
                        .collect(),
                    remediation: record.remediation().map(str::to_owned),
                    comparison_profile: profiled
                        .then_some(wordpress_comparison_profile(record.comparison_profile())),
                    version_resolution: evaluation
                        .version_resolution()
                        .map(wordpress_version_resolution),
                    version_resolution_reason: evaluation
                        .version_resolution_reason()
                        .map(wordpress_version_resolution_reason),
                    component_evidence: wordpress_evidence_class(evaluation.component_evidence()),
                    version_relation: wordpress_version_relation(evaluation.version_relation()),
                    applicability: wordpress_applicability(evaluation.applicability()),
                    exploit_execution: wordpress_execution(evaluation.exploit_execution()),
                    impact_validation: wordpress_execution(evaluation.impact_validation()),
                }
            })
            .collect::<Vec<_>>();
        let review_basis_schema = if source_identity_external_schema {
            "security.wordpress-review-audit/v6"
        } else if explicit_external_schema {
            "security.wordpress-review-audit/v5"
        } else if external_schema {
            "security.wordpress-review-audit/v4"
        } else if inventory_schema {
            "security.wordpress-review-audit/v3"
        } else if profiled {
            "security.wordpress-review-audit/v2"
        } else {
            "security.wordpress-review-audit/v1"
        };
        let discovery_influenced = audit.discovery().is_some();
        Self {
            schema: if discovery_influenced {
                "security.wordpress-review-audit/v7"
            } else {
                review_basis_schema
            },
            review_basis_schema: discovery_influenced.then_some(review_basis_schema),
            capability_id: WORDPRESS_REVIEW_CAPABILITY_ID,
            catalog_status: wordpress_catalog_status(result.catalog_status()),
            catalog_schema: if inventory_schema && !external_schema {
                result
                    .catalog_schema()
                    .map(WordPressAdvisoryCatalogSchema::id)
            } else {
                None
            },
            catalog,
            inventory_import,
            external_review,
            signal_count: audit.signal_count(),
            evidence_reference_count: audit.evidence_reference_count(),
            additional_request_count: audit.additional_request_count(),
            item_projected: audit.item_projected(),
            component_count: components.len(),
            advisory_count: advisories.len(),
            components,
            advisories,
        }
    }

    fn validate(&self, items: &[AssessmentItemDocument<'_>]) -> Result<(), ReportError> {
        let projected = items
            .iter()
            .filter(|item| item.capability_id == WORDPRESS_REVIEW_CAPABILITY_ID)
            .count();
        let discovery_influenced = self.schema == "security.wordpress-review-audit/v7";
        let review_basis_schema = if discovery_influenced {
            self.review_basis_schema.unwrap_or("")
        } else {
            self.schema
        };
        let external = matches!(
            review_basis_schema,
            "security.wordpress-review-audit/v4"
                | "security.wordpress-review-audit/v5"
                | "security.wordpress-review-audit/v6"
        );
        let source_identity_external = review_basis_schema == "security.wordpress-review-audit/v6";
        let explicit_external = match review_basis_schema {
            "security.wordpress-review-audit/v5" => true,
            "security.wordpress-review-audit/v6" => self
                .external_review
                .as_ref()
                .is_some_and(|review| review.comparison_profile.is_some()),
            _ => false,
        };
        let catalog_consistent = if external {
            self.catalog_status == "evaluated" && self.catalog.is_none()
        } else {
            matches!(
                (self.catalog_status, self.catalog.as_ref()),
                ("catalogue_not_supplied", None) | ("evaluated", Some(_))
            )
        };
        let version_evidence_count = self
            .components
            .iter()
            .try_fold(0_usize, |count, component| {
                count.checked_add(component.versions.len())
            });
        let discovery_evidence_present = self.components.iter().any(|component| {
            component
                .identity_sources
                .contains(&"theme_stylesheet_declaration")
                || component
                    .versions
                    .iter()
                    .any(|version| version.source == "theme_stylesheet_declaration")
        });
        let inventory = review_basis_schema == "security.wordpress-review-audit/v3";
        let profiled = review_basis_schema == "security.wordpress-review-audit/v2"
            || (inventory && self.catalog_schema == Some(WORDPRESS_ADVISORY_CATALOG_SCHEMA_V2));
        let basis_schema_valid = matches!(
            review_basis_schema,
            "security.wordpress-review-audit/v1"
                | "security.wordpress-review-audit/v2"
                | "security.wordpress-review-audit/v3"
                | "security.wordpress-review-audit/v4"
                | "security.wordpress-review-audit/v5"
                | "security.wordpress-review-audit/v6"
        );
        let schema_valid = basis_schema_valid
            && if discovery_influenced {
                self.review_basis_schema == Some(review_basis_schema)
            } else {
                self.review_basis_schema.is_none()
            };
        let catalogue_schema_valid = if external {
            self.catalog_schema.is_none()
        } else if inventory {
            matches!(
                (self.catalog_status, self.catalog_schema),
                ("catalogue_not_supplied", None)
                    | (
                        "evaluated",
                        Some(
                            WORDPRESS_ADVISORY_CATALOG_SCHEMA
                                | WORDPRESS_ADVISORY_CATALOG_SCHEMA_V2
                        )
                    )
            )
        } else {
            self.catalog_schema.is_none()
        };
        let inventory_valid = match (&self.inventory_import, inventory, external) {
            (Some(import), true, false) | (Some(import), false, true) => {
                import.is_valid(&self.components)
            },
            (None, false, _) => self
                .components
                .iter()
                .all(|component| component.inventory_status.is_none()),
            _ => false,
        };
        let external_valid = match (&self.external_review, external) {
            (Some(review), true) => review.is_valid(
                &self.components,
                explicit_external,
                source_identity_external,
            ),
            (None, false) => true,
            _ => false,
        };
        if !schema_valid
            || self.capability_id != WORDPRESS_REVIEW_CAPABILITY_ID
            || !catalog_consistent
            || !catalogue_schema_valid
            || !inventory_valid
            || !external_valid
            || (!discovery_influenced && discovery_evidence_present)
            || if discovery_influenced {
                self.additional_request_count > MAX_WORDPRESS_DISCOVERY_AUDIT_REQUESTS
            } else {
                self.additional_request_count != 0
            }
            || usize::from(self.signal_count) > MAX_WORDPRESS_SIGNALS
            || usize::from(self.evidence_reference_count) > MAX_WORDPRESS_SIGNALS
            || self.component_count != self.components.len()
            || self.component_count > MAX_WORDPRESS_RESULT_COMPONENTS
            || version_evidence_count
                .is_none_or(|count| count > MAX_WORDPRESS_RESULT_VERSION_EVIDENCE)
            || self.advisory_count != self.advisories.len()
            || self.advisory_count > MAX_WORDPRESS_ADVISORY_RECORDS
            || (external && self.advisory_count != 0)
            || projected > 1
            || self.item_projected != (projected == 1)
            || self.item_projected != (self.signal_count > 0)
            || self.item_projected != (self.evidence_reference_count > 0)
            || ((review_basis_schema == "security.wordpress-review-audit/v2" || external)
                && self.catalog_status != "evaluated")
            || self
                .advisories
                .iter()
                .any(|advisory| !advisory.profile_fields_are_valid(profiled))
        {
            return Err(ReportError::Serialization);
        }
        Ok(())
    }

    fn wire_json(&self) -> Result<String, ReportError> {
        serde_json::to_string(self).map_err(|_| ReportError::Serialization)
    }

    fn metadata(&self) -> Vec<(&'static str, String)> {
        let mut metadata = vec![
            ("Audit schema", self.schema.to_owned()),
            ("Capability", self.capability_id.to_owned()),
            ("Catalog status", self.catalog_status.to_owned()),
            ("Signal count", self.signal_count.to_string()),
            (
                "Evidence reference count",
                self.evidence_reference_count.to_string(),
            ),
            (
                "Additional request count",
                self.additional_request_count.to_string(),
            ),
            ("Item projected", self.item_projected.to_string()),
            ("Component count", self.component_count.to_string()),
            ("Advisory count", self.advisory_count.to_string()),
        ];
        if let Some(schema) = self.review_basis_schema {
            metadata.insert(1, ("Review basis schema", schema.to_owned()));
        }
        metadata
    }

    fn presentation_counts(&self) -> WordPressPresentationCounts {
        let mut counts = WordPressPresentationCounts {
            review_candidates: 0,
            contradicted: 0,
            limitations: 0,
            source_guidance: self.external_review.as_ref().map_or(0, |external| {
                let evaluated = external
                    .evaluations
                    .iter()
                    .filter(|evaluation| external_evaluation_has_source_guidance(evaluation))
                    .count();
                let limitations = external
                    .identity_limitations
                    .as_ref()
                    .map_or(0, |limitations| {
                        limitations
                            .iter()
                            .filter(|limitation| {
                                limitation.source_patched
                                    || !limitation.source_patched_versions.is_empty()
                                    || !limitation.source_remediation.is_empty()
                            })
                            .count()
                    });
                evaluated + limitations
            }),
        };
        if let Some(external) = &self.external_review {
            for evaluation in &external.evaluations {
                match wordpress_external_advisory_group(evaluation) {
                    WordPressPresentationGroup::ReviewCandidate => counts.review_candidates += 1,
                    WordPressPresentationGroup::Contradicted => counts.contradicted += 1,
                    WordPressPresentationGroup::Limitation => counts.limitations += 1,
                }
            }
            counts.limitations = counts
                .limitations
                .saturating_add(external.identity_limitations.as_ref().map_or(0, Vec::len))
                .saturating_add(
                    external
                        .counts
                        .unprojected_identity_limitations
                        .unwrap_or(0),
                );
        }
        for advisory in &self.advisories {
            match wordpress_advisory_group(advisory) {
                WordPressPresentationGroup::ReviewCandidate => counts.review_candidates += 1,
                WordPressPresentationGroup::Contradicted => counts.contradicted += 1,
                WordPressPresentationGroup::Limitation => counts.limitations += 1,
            }
            if advisory_has_source_guidance(advisory) {
                counts.source_guidance += 1;
            }
        }
        counts
    }
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
impl AssessmentWordPressDiscoveryAuditDocument {
    fn from_wordpress_audit(
        audit: &WebAssessmentWordPressAudit,
        evidence_references: &[String],
    ) -> Result<Option<Self>, ReportError> {
        let Some(discovery) = audit.discovery() else {
            if evidence_references.is_empty() {
                return Ok(None);
            }
            return Err(ReportError::Serialization);
        };
        let mut evidence_references = evidence_references.iter();
        let sources = discovery
            .sources()
            .iter()
            .map(|source| {
                let evidence_reference_count = source.evidence_ids().len();
                let source_evidence_references = evidence_references
                    .by_ref()
                    .take(evidence_reference_count)
                    .cloned()
                    .collect::<Vec<_>>();
                if source_evidence_references.len() != evidence_reference_count {
                    return Err(ReportError::Serialization);
                }
                let component =
                    source
                        .component_kind()
                        .zip(source.component_slug())
                        .map(|(kind, slug)| WordPressComponentIdentityDocument {
                            kind: wordpress_component_kind(kind),
                            slug: slug.to_owned(),
                        });
                let theme = source
                    .theme()
                    .map(|metadata| WordPressThemeDiscoveryDocument {
                        name: metadata.name().map(str::to_owned),
                        version: metadata.version().map(str::to_owned),
                        template: metadata.template().map(str::to_owned),
                        requires_wordpress: metadata.requires_wordpress().map(str::to_owned),
                        requires_php: metadata.requires_php().map(str::to_owned),
                        tested_up_to: metadata.tested_up_to().map(str::to_owned),
                    });
                let plugin = source
                    .plugin()
                    .map(|metadata| WordPressPluginDiscoveryDocument {
                        name: metadata.name().map(str::to_owned),
                        stable_tag: metadata.stable_tag().map(str::to_owned),
                        requires_wordpress: metadata.requires_wordpress().map(str::to_owned),
                        requires_php: metadata.requires_php().map(str::to_owned),
                        tested_up_to: metadata.tested_up_to().map(str::to_owned),
                    });
                Ok(WordPressDiscoverySourceDocument {
                    kind: source.kind().as_str(),
                    component,
                    parent_depth: source.parent_depth(),
                    outcome: source.outcome().as_str(),
                    request_attempted: source.request_attempted(),
                    response_bytes: source.response_bytes(),
                    evidence_reference_count,
                    evidence_references: source_evidence_references,
                    namespaces: source.namespaces().to_vec(),
                    theme,
                    plugin,
                })
            })
            .collect::<Result<Vec<_>, ReportError>>()?;
        if evidence_references.next().is_some() {
            return Err(ReportError::Serialization);
        }
        Ok(Some(Self {
            schema: WORDPRESS_DISCOVERY_AUDIT_SCHEMA,
            capability_id: WORDPRESS_DISCOVERY_CAPABILITY_ID,
            policy_id: discovery.policy_id(),
            selected: discovery.selected(),
            method: "get",
            credential_mode: "anonymous",
            seed_count: discovery.seed_count(),
            candidate_count: discovery.candidate_count(),
            candidate_limit_reached: discovery.candidate_limit_reached(),
            omitted_candidate_count: discovery.omitted_candidate_count(),
            attempted_request_count: discovery.attempted_request_count(),
            completed_response_count: discovery.completed_response_count(),
            committed_response_count: discovery.committed_response_count(),
            response_bytes: discovery.response_bytes(),
            source_count: sources.len(),
            sources,
        }))
    }

    fn validate(&self) -> Result<(), ReportError> {
        let source_bytes = self.sources.iter().try_fold(0_u64, |total, source| {
            total.checked_add(source.response_bytes)
        });
        let evidence_references = self.sources.iter().try_fold(0_usize, |total, source| {
            total.checked_add(source.evidence_reference_count)
        });
        let unique_evidence_references = self
            .sources
            .iter()
            .flat_map(|source| source.evidence_references.iter())
            .collect::<std::collections::BTreeSet<_>>()
            .len();
        let attempted_sources = self
            .sources
            .iter()
            .filter(|source| source.request_attempted)
            .count();
        let attempted_rest_sources = self
            .sources
            .iter()
            .filter(|source| source.request_attempted && source.kind == "rest_index")
            .count();
        let attempted_theme_sources = self
            .sources
            .iter()
            .filter(|source| source.request_attempted && source.kind == "theme_stylesheet")
            .count();
        let attempted_plugin_sources = self
            .sources
            .iter()
            .filter(|source| source.request_attempted && source.kind == "plugin_readme")
            .count();
        let unique_source_count = self
            .sources
            .iter()
            .map(|source| {
                (
                    source.kind,
                    source
                        .component
                        .as_ref()
                        .map(|component| (component.kind, component.slug.as_str())),
                    source.parent_depth,
                )
            })
            .collect::<std::collections::BTreeSet<_>>()
            .len();
        if self.schema != WORDPRESS_DISCOVERY_AUDIT_SCHEMA
            || self.capability_id != WORDPRESS_DISCOVERY_CAPABILITY_ID
            || self.policy_id != WORDPRESS_DISCOVERY_POLICY_ID
            || !self.selected
            || self.method != "get"
            || self.credential_mode != "anonymous"
            || usize::from(self.seed_count) > MAX_WORDPRESS_DISCOVERY_AUDIT_SOURCES
            || usize::from(self.candidate_count) > MAX_WORDPRESS_DISCOVERY_AUDIT_SOURCES
            || self.seed_count > self.candidate_count
            || self.candidate_limit_reached != (self.omitted_candidate_count > 0)
            || self.omitted_candidate_count > MAX_WORDPRESS_DISCOVERY_AUDIT_OMITTED_CANDIDATES
            || (self.omitted_candidate_count > 0
                && usize::from(self.candidate_count) != MAX_WORDPRESS_DISCOVERY_AUDIT_SOURCES)
            || self.attempted_request_count > MAX_WORDPRESS_DISCOVERY_AUDIT_REQUESTS
            || self.attempted_request_count > self.candidate_count
            || attempted_sources != usize::from(self.attempted_request_count)
            || attempted_rest_sources > MAX_WORDPRESS_DISCOVERY_AUDIT_REST_REQUESTS
            || attempted_theme_sources > MAX_WORDPRESS_DISCOVERY_AUDIT_THEME_REQUESTS
            || attempted_plugin_sources > MAX_WORDPRESS_DISCOVERY_AUDIT_PLUGIN_REQUESTS
            || self.completed_response_count > self.attempted_request_count
            || self.committed_response_count != self.completed_response_count
            || self.source_count != self.sources.len()
            || self.source_count > MAX_WORDPRESS_DISCOVERY_AUDIT_SOURCES
            || unique_source_count != self.source_count
            || usize::from(self.candidate_count) != self.source_count
            || source_bytes != Some(self.response_bytes)
            || evidence_references != Some(usize::from(self.committed_response_count))
            || unique_evidence_references != usize::from(self.committed_response_count)
            || self.sources.iter().any(|source| !source.is_valid())
        {
            return Err(ReportError::Serialization);
        }
        Ok(())
    }

    fn metadata(&self) -> [(&'static str, String); 11] {
        [
            ("Discovery audit schema", self.schema.to_owned()),
            ("Discovery policy", self.policy_id.to_owned()),
            ("Request method", self.method.to_owned()),
            ("Credential mode", self.credential_mode.to_owned()),
            ("Root-derived seeds", self.seed_count.to_string()),
            ("Selected candidates", self.candidate_count.to_string()),
            (
                "Candidate limit reached",
                self.candidate_limit_reached.to_string(),
            ),
            (
                "Omitted candidates",
                self.omitted_candidate_count.to_string(),
            ),
            (
                "Attempted requests",
                self.attempted_request_count.to_string(),
            ),
            (
                "Completed responses",
                self.completed_response_count.to_string(),
            ),
            ("Discovery response bytes", self.response_bytes.to_string()),
        ]
    }

    fn wire_json(&self) -> Result<String, ReportError> {
        serde_json::to_string(self).map_err(|_| ReportError::Serialization)
    }
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
fn wordpress_discovery_matches_review(
    review: &AssessmentWordPressAuditDocument,
    discovery: &AssessmentWordPressDiscoveryAuditDocument,
) -> bool {
    for source in &discovery.sources {
        if source.parent_depth != 0 || !matches!(source.kind, "theme_stylesheet" | "plugin_readme")
        {
            continue;
        }
        let Some(source_component) = source.component.as_ref() else {
            return false;
        };
        let Some(review_component) = review.components.iter().find(|component| {
            component.identity.kind == source_component.kind
                && component.identity.slug == source_component.slug
        }) else {
            return false;
        };
        if !review_component
            .identity_sources
            .contains(&"same_origin_asset_path")
        {
            return false;
        }
    }

    let mut discovered = std::collections::BTreeMap::new();
    for source in &discovery.sources {
        if source.kind != "theme_stylesheet" {
            continue;
        }
        let Some(version) = source
            .theme
            .as_ref()
            .and_then(|theme| theme.version.as_deref())
        else {
            continue;
        };
        let Some(component) = source.component.as_ref() else {
            return false;
        };
        if source.outcome != "observed"
            || component.kind != "theme"
            || discovered
                .insert((component.kind, component.slug.as_str()), version)
                .is_some()
        {
            return false;
        }
    }

    let mut reviewed = std::collections::BTreeMap::new();
    for component in &review.components {
        for version in &component.versions {
            if version.source != "theme_stylesheet_declaration" {
                continue;
            }
            if component.identity.kind != "theme"
                || reviewed
                    .insert(
                        (component.identity.kind, component.identity.slug.as_str()),
                        version.value.as_str(),
                    )
                    .is_some()
            {
                return false;
            }
        }
    }
    discovered == reviewed
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
impl WordPressDiscoverySourceDocument {
    fn is_valid(&self) -> bool {
        let component_valid = self.component.as_ref().is_none_or(|component| {
            matches!(component.kind, "core" | "plugin" | "theme")
                && crate::wordpress_review::valid_slug(&component.slug)
                && ((component.kind == "core") == (component.slug == "wordpress"))
        });
        let strings_valid = self
            .namespaces
            .iter()
            .all(|value| valid_wordpress_discovery_namespace(value))
            && self
                .theme
                .as_ref()
                .is_none_or(WordPressThemeDiscoveryDocument::is_valid)
            && self
                .plugin
                .as_ref()
                .is_none_or(WordPressPluginDiscoveryDocument::is_valid);
        let source_shape_valid = match self.kind {
            "rest_index" => {
                self.component.is_none()
                    && self.parent_depth == 0
                    && self.theme.is_none()
                    && self.plugin.is_none()
            },
            "theme_stylesheet" => {
                self.component
                    .as_ref()
                    .is_some_and(|component| component.kind == "theme")
                    && self.parent_depth <= 1
                    && self.namespaces.is_empty()
                    && self.plugin.is_none()
            },
            "plugin_readme" => {
                self.component
                    .as_ref()
                    .is_some_and(|component| component.kind == "plugin")
                    && self.parent_depth == 0
                    && self.namespaces.is_empty()
                    && self.theme.is_none()
            },
            _ => false,
        };
        let observed_shape_valid = match self.kind {
            "rest_index" => !self.namespaces.is_empty(),
            "theme_stylesheet" => self
                .theme
                .as_ref()
                .is_some_and(|metadata| metadata.name.is_some()),
            "plugin_readme" => self
                .plugin
                .as_ref()
                .is_some_and(|metadata| metadata.name.is_some()),
            _ => false,
        };
        let completed_response = matches!(
            self.outcome,
            "observed"
                | "no_metadata"
                | "not_found"
                | "unauthorized"
                | "rate_limited"
                | "redirect_observed"
                | "unsupported_content"
                | "malformed"
                | "truncated"
        );
        let outcome_valid = completed_response
            || matches!(
                self.outcome,
                "invalid_advertisement"
                    | "request_failed"
                    | "budget_exhausted"
                    | "cancelled"
                    | "deadline_exceeded"
                    | "not_selected_by_limit"
                    | "not_attempted_after_throttle"
            );
        let metadata_absent =
            self.namespaces.is_empty() && self.theme.is_none() && self.plugin.is_none();
        let definitely_not_dispatched = matches!(
            self.outcome,
            "invalid_advertisement" | "not_selected_by_limit" | "not_attempted_after_throttle"
        );
        component_valid
            && strings_valid
            && source_shape_valid
            && outcome_valid
            && self.evidence_reference_count == usize::from(completed_response)
            && self.evidence_references.len() == self.evidence_reference_count
            && self
                .evidence_references
                .iter()
                .all(|reference| valid_opaque_assessment_reference(reference, "evidence"))
            && (!completed_response || self.request_attempted)
            && (self.request_attempted || self.response_bytes == 0)
            && (!definitely_not_dispatched || !self.request_attempted)
            && (if self.outcome == "observed" {
                observed_shape_valid
            } else {
                metadata_absent
            })
            && self.namespaces.len() <= MAX_WORDPRESS_DISCOVERY_AUDIT_NAMESPACES
    }
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
impl WordPressThemeDiscoveryDocument {
    fn is_valid(&self) -> bool {
        [
            self.name.as_deref(),
            self.template.as_deref(),
            self.requires_wordpress.as_deref(),
            self.requires_php.as_deref(),
            self.tested_up_to.as_deref(),
        ]
        .into_iter()
        .flatten()
        .all(valid_wordpress_discovery_metadata)
            && self
                .version
                .as_deref()
                .is_none_or(valid_wordpress_discovery_version)
    }
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
impl WordPressPluginDiscoveryDocument {
    fn is_valid(&self) -> bool {
        [
            self.name.as_deref(),
            self.stable_tag.as_deref(),
            self.requires_wordpress.as_deref(),
            self.requires_php.as_deref(),
            self.tested_up_to.as_deref(),
        ]
        .into_iter()
        .flatten()
        .all(valid_wordpress_discovery_metadata)
    }
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
fn valid_wordpress_discovery_metadata(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_WORDPRESS_DISCOVERY_AUDIT_METADATA_BYTES
        && !value.chars().any(char::is_control)
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
fn valid_wordpress_discovery_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_WORDPRESS_DISCOVERY_AUDIT_VERSION_BYTES
        && !value.chars().any(char::is_control)
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
fn valid_wordpress_discovery_namespace(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_WORDPRESS_DISCOVERY_AUDIT_NAMESPACE_BYTES
        && value.is_ascii()
        && !value.chars().any(char::is_control)
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
fn wordpress_external_advisory_group(
    evaluation: &WordPressExternalEvaluationDocument,
) -> WordPressPresentationGroup {
    match evaluation.applicability {
        "version_match_under_selected_policy" => WordPressPresentationGroup::ReviewCandidate,
        "no_version_match_under_selected_policy" => WordPressPresentationGroup::Contradicted,
        _ => WordPressPresentationGroup::Limitation,
    }
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
fn wordpress_advisory_group(advisory: &WordPressAdvisoryDocument) -> WordPressPresentationGroup {
    match advisory.applicability {
        "candidate_match_on_declared_facts" => WordPressPresentationGroup::ReviewCandidate,
        "contradicted_by_declared_facts" => WordPressPresentationGroup::Contradicted,
        _ => WordPressPresentationGroup::Limitation,
    }
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
fn advisory_has_source_guidance(advisory: &WordPressAdvisoryDocument) -> bool {
    !advisory.fixed_versions.is_empty() || advisory.remediation.is_some()
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
fn external_evaluation_has_source_guidance(
    evaluation: &WordPressExternalEvaluationDocument,
) -> bool {
    evaluation.source_patched
        || !evaluation.source_patched_versions.is_empty()
        || !evaluation.source_remediation.is_empty()
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
struct WordPressExternalComponentValidation<'a> {
    component: &'a WordPressComponentDocument,
    evidence_status: &'static str,
    evidence_row_count: usize,
    distinct_spelling_count: usize,
    semantic_status: Option<&'static str>,
    semantic_reason: Option<&'static str>,
    selected_version: Option<crate::wordpress_version::ProfiledVersionKey>,
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
impl WordPressExternalReviewDocument {
    fn external_collection_limit(&self) -> usize {
        const RESOURCE_V1_COLLECTION_LIMIT: usize = 64;
        if matches!(
            self.resource_policy,
            Some(WORDFENCE_V3_RESOURCE_POLICY_V2 | WORDFENCE_V3_RESOURCE_POLICY_V3)
        ) {
            crate::wordpress_review::MAX_WORDFENCE_V3_RANGES_PER_ASSOCIATION
        } else {
            RESOURCE_V1_COLLECTION_LIMIT
        }
    }

    fn external_description_limit(&self) -> usize {
        const RESOURCE_V1_DESCRIPTION_LIMIT: usize = 2_048;
        const RESOURCE_V2_DESCRIPTION_LIMIT: usize = 4_096;
        if matches!(
            self.resource_policy,
            Some(WORDFENCE_V3_RESOURCE_POLICY_V2 | WORDFENCE_V3_RESOURCE_POLICY_V3)
        ) {
            RESOURCE_V2_DESCRIPTION_LIMIT
        } else {
            RESOURCE_V1_DESCRIPTION_LIMIT
        }
    }

    fn accounted_retained_limit(&self) -> usize {
        const RESOURCE_V1_RETAINED_INDEX_LIMIT: usize = 64 * 1_024 * 1_024;
        const RESOURCE_V2_RETAINED_INDEX_LIMIT: usize = 128 * 1_024 * 1_024;
        match self.resource_policy {
            Some(WORDFENCE_V3_RESOURCE_POLICY_V3) => {
                crate::wordpress_review::MAX_WORDFENCE_V3_RETAINED_BYTES
            },
            Some(WORDFENCE_V3_RESOURCE_POLICY_V2) => RESOURCE_V2_RETAINED_INDEX_LIMIT,
            _ => RESOURCE_V1_RETAINED_INDEX_LIMIT,
        }
    }

    fn source_identity_contract_is_valid(&self, source_identity: bool) -> bool {
        let identity_counts = [
            self.counts.exact_identity_associations,
            self.counts.candidate_identity_associations,
            self.counts.ambiguous_identity_associations,
            self.counts.unresolved_identity_associations,
        ];
        if !source_identity {
            return self.mapping_revision == WORDFENCE_V3_MAPPING_REVISION
                && self.identity_mapping_policy.is_none()
                && self.identity_source_assurance.is_none()
                && self.resource_policy.is_none()
                && self.input.accounted_retained_bytes.is_none()
                && self.counts.mapped_unselected_associations.is_none()
                && self.counts.projected_identity_limitations.is_none()
                && self.counts.unprojected_identity_limitations.is_none()
                && identity_counts.iter().all(Option::is_none)
                && self.evaluations.iter().all(|evaluation| {
                    evaluation.identity_mapping.is_none()
                        && evaluation.identity_collision_raw_count.is_none()
                        && evaluation.key.source_component.is_none()
                        && evaluation.key.source_association_fingerprint.is_none()
                })
                && self.identity_limitations.is_none();
        }

        let [Some(exact), Some(candidate), Some(ambiguous), Some(unresolved)] = identity_counts
        else {
            return false;
        };
        let mapping_revision_is_valid = match self.mapping_revision {
            WORDFENCE_V3_MAPPING_REVISION => candidate == 0 && ambiguous == 0 && unresolved == 0,
            WORDFENCE_V3_MAPPING_REVISION_V2 => candidate != 0 || ambiguous != 0 || unresolved != 0,
            _ => false,
        };
        let resource_policy_is_valid = matches!(
            self.resource_policy,
            Some(
                WORDFENCE_V3_RESOURCE_POLICY_V1
                    | WORDFENCE_V3_RESOURCE_POLICY_V2
                    | WORDFENCE_V3_RESOURCE_POLICY_V3
            )
        );
        let v6_is_required = self.mapping_revision == WORDFENCE_V3_MAPPING_REVISION_V2
            || self.resource_policy != Some(WORDFENCE_V3_RESOURCE_POLICY_V1);
        let limitations_match = match (
            self.counts.projected_identity_limitations,
            self.counts.unprojected_identity_limitations,
            self.identity_limitations.as_ref(),
        ) {
            (Some(projected), Some(unprojected), Some(limitations)) => {
                projected == limitations.len()
                    && projected <= MAX_WORDPRESS_EXTERNAL_IDENTITY_LIMITATION_PROJECTIONS
                    && projected.checked_add(unprojected) == Some(unresolved)
            },
            _ => false,
        };
        let excluded_partition_matches = self
            .counts
            .mapped_unselected_associations
            .and_then(|mapped| mapped.checked_add(unresolved))
            == Some(self.counts.excluded_associations);
        mapping_revision_is_valid
            && self.identity_mapping_policy == Some(WORDFENCE_V3_IDENTITY_MAPPING_POLICY)
            && self.identity_source_assurance == Some("not_established")
            && resource_policy_is_valid
            && v6_is_required
            && limitations_match
            && excluded_partition_matches
            && self.input.accounted_retained_bytes.is_some()
            && exact
                .checked_add(candidate)
                .and_then(|count| count.checked_add(ambiguous))
                .and_then(|count| count.checked_add(unresolved))
                == Some(self.counts.software_associations)
    }

    fn is_valid(
        &self,
        components: &[WordPressComponentDocument],
        explicit: bool,
        source_identity: bool,
    ) -> bool {
        let selected_profile = match (
            explicit,
            self.comparison_profile,
            self.policy_selection,
            self.source_semantics_assurance,
        ) {
            (false, None, None, None) => None,
            (
                true,
                Some(profile @ ("numeric-dotted/v1" | "php-release-subset/v1")),
                Some("explicit_operator"),
                Some("not_established"),
            ) => Some(profile),
            _ => return false,
        };
        if self.source_namespace != "wordfence-intelligence"
            || self.source_format != "wordfence-v3-production"
            || !self.source_identity_contract_is_valid(source_identity)
            || (!explicit
                && self.comparison_policy
                    != WordPressExternalComparisonPolicy::WordfenceV3SourceSemanticsUnresolvedV1
                        .id())
            || (explicit
                && self.comparison_policy
                    != WordPressExternalComparisonPolicy::TermivarWordfenceV3ExplicitInterpretationV1
                        .id())
            || self.input.byte_length == 0
            || self.input.byte_length
                > crate::wordpress_review::MAX_WORDFENCE_V3_PRODUCTION_BYTES as u64
            || !valid_lowercase_sha256(&self.input.sha256)
            || !valid_lowercase_sha256(&self.input.semantic_sha256)
            || self
                .input
                .accounted_retained_bytes
                .is_some_and(|bytes| bytes == 0 || bytes > self.accounted_retained_limit())
            || self.counts.parsed_records > crate::wordpress_review::MAX_WORDFENCE_V3_RECORDS
            || self.counts.software_associations
                > crate::wordpress_review::MAX_WORDFENCE_V3_SOFTWARE_ASSOCIATIONS
            || self.counts.selected_associations != self.evaluations.len()
            || self.counts.selected_associations > MAX_WORDPRESS_ADVISORY_RECORDS
            || self.notices.len() > MAX_WORDPRESS_ADVISORY_RECORDS
            || !wordpress_external_source_counts_are_valid(
                self.counts.parsed_records,
                self.counts.software_associations,
            )
            || self
                .counts
                .selected_associations
                .checked_add(self.counts.excluded_associations)
                != Some(self.counts.software_associations)
            || self
                .counts
                .evaluable_associations
                .checked_add(self.counts.unsupported_associations)
                != Some(self.counts.selected_associations)
            || !self.counts.is_valid(explicit)
        {
            return false;
        }

        let mut notices_by_id = std::collections::BTreeMap::new();
        let notices_are_valid = self.notices.iter().all(|notice| {
            valid_prefixed_lowercase_sha256(&notice.id, "wordfence-notice-sha256:")
                && notices_by_id.insert(notice.id.as_str(), notice).is_none()
        });
        if !notices_are_valid || !self.notices.windows(2).all(|pair| pair[0].id < pair[1].id) {
            return false;
        }

        let mut resolution_work = 0_usize;
        let mut component_validations = std::collections::BTreeMap::new();
        for component in components {
            if selected_profile.is_some() {
                let Some(next_work) = resolution_work.checked_add(component.versions.len()) else {
                    return false;
                };
                resolution_work = next_work;
                if resolution_work > crate::wordpress_review::MAX_WORDPRESS_VERSION_RESOLUTION_WORK
                {
                    return false;
                }
            }
            let Some(validation) = external_component_validation(component, selected_profile)
            else {
                return false;
            };
            if component_validations
                .insert(
                    (component.identity.kind, component.identity.slug.as_str()),
                    validation,
                )
                .is_some()
            {
                return false;
            }
        }

        let mut evaluation_ids = std::collections::BTreeSet::new();
        let mut source_association_base_ids = std::collections::BTreeSet::new();
        let mut referenced_notices = std::collections::BTreeSet::new();
        let mut interpretation_work = 0_usize;
        let mut selected_identity_counts = [0_usize; 3];
        let collection_limit = self.external_collection_limit();
        let description_limit = self.external_description_limit();
        let expanded_source_values = matches!(
            self.resource_policy,
            Some(WORDFENCE_V3_RESOURCE_POLICY_V2 | WORDFENCE_V3_RESOURCE_POLICY_V3)
        );
        let evaluations_are_valid = self.evaluations.iter().all(|evaluation| {
            let Some(profiled_validation) = component_validations.get(&(
                evaluation.key.component.kind,
                evaluation.key.component.slug.as_str(),
            )) else {
                return false;
            };
            let Some(identity_mapping) =
                external_identity_mapping_is_valid(evaluation, source_identity)
            else {
                return false;
            };
            if evaluation
                .identity_collision_raw_count
                .is_some_and(|count| count > self.counts.software_associations)
            {
                return false;
            }
            selected_identity_counts[match identity_mapping {
                WordfenceV3IdentityMapping::Exact => 0,
                WordfenceV3IdentityMapping::AsciiCaseFoldCandidate => 1,
                WordfenceV3IdentityMapping::AsciiCaseFoldAmbiguous => 2,
            }] += 1;
            let unprofiled_validation;
            let validation = if explicit && identity_mapping != WordfenceV3IdentityMapping::Exact {
                unprofiled_validation =
                    external_component_validation(profiled_validation.component, None);
                let Some(validation) = unprofiled_validation.as_ref() else {
                    return false;
                };
                validation
            } else {
                profiled_validation
            };
            let component = validation.component;
            if explicit && identity_mapping == WordfenceV3IdentityMapping::Exact {
                let Some(next_work) =
                    crate::wordpress_version::checked_accumulate_external_interpretation_work(
                        interpretation_work,
                        evaluation.affected_ranges.len(),
                        evaluation.source_patched_versions.len(),
                        crate::wordpress_review::MAX_WORDPRESS_EVALUATION_WORK,
                    )
                else {
                    return false;
                };
                interpretation_work = next_work;
            } else if explicit {
                let Some(next_work) =
                    interpretation_work.checked_add(evaluation.affected_ranges.len())
                else {
                    return false;
                };
                interpretation_work = next_work;
                if interpretation_work > crate::wordpress_review::MAX_WORDPRESS_EVALUATION_WORK {
                    return false;
                }
            }
            let source_kind = evaluation
                .key
                .source_component
                .as_ref()
                .map_or(evaluation.key.component.kind, |source| source.kind);
            let source_slug = evaluation
                .key
                .source_component
                .as_ref()
                .map_or(evaluation.key.component.slug.as_str(), |source| {
                    source.slug.as_str()
                });
            let identity = (
                evaluation.key.source_namespace.as_str(),
                evaluation.key.upstream_id.as_str(),
                evaluation.key.component.kind,
                evaluation.key.component.slug.as_str(),
                source_kind,
                source_slug,
                evaluation.key.source_association_fingerprint.as_deref(),
            );
            let source_association_base_is_unique = source_association_base_ids.insert((
                evaluation.key.source_namespace.as_str(),
                evaluation.key.upstream_id.as_str(),
                source_kind,
                source_slug,
            ));
            let mut local_notices = std::collections::BTreeSet::new();
            let evaluation_notices_are_valid = evaluation.notice_ids.iter().all(|id| {
                if notices_by_id.contains_key(id.as_str()) && local_notices.insert(id.as_str()) {
                    referenced_notices.insert(id.clone());
                    true
                } else {
                    false
                }
            });
            let has_defiant_notice = evaluation.notice_ids.iter().any(|id| {
                notices_by_id
                    .get(id.as_str())
                    .is_some_and(|notice| notice.party == "defiant")
            });
            let expected_record_reference =
                wordpress_external_record_reference(&evaluation.references);
            let validated_version = external_version_evidence_resolution_is_valid(
                &evaluation.version_evidence_resolution,
                validation,
            );
            evaluation.key.source_namespace == self.source_namespace
                && valid_lowercase_uuid(&evaluation.key.upstream_id)
                && evaluation_ids.insert(identity)
                && (expanded_source_values || source_association_base_is_unique)
                && component.evidence_class == evaluation.component_evidence
                && (!source_identity
                    || evaluation
                        .key
                        .source_association_fingerprint
                        .as_deref()
                        .is_some_and(|fingerprint| {
                            valid_prefixed_lowercase_sha256(
                                fingerprint,
                                "wordfence-source-association-sha256:",
                            )
                        }))
                && validated_version.is_some()
                && evaluation.references.len()
                    <= crate::wordpress_review::MAX_WORDFENCE_V3_REFERENCES
                && external_researchers_are_valid(&evaluation.researchers, expanded_source_values)
                && evaluation.description.len() <= description_limit
                && evaluation
                    .cwe
                    .as_ref()
                    .is_none_or(|cwe| cwe.description.len() <= description_limit)
                && evaluation.affected_ranges.len() <= collection_limit
                && evaluation.source_patched_versions.len() <= collection_limit
                && external_source_versions_are_valid(
                    &evaluation.source_patched_versions,
                    expanded_source_values,
                )
                && evaluation.notice_ids.len()
                    <= crate::wordpress_review::MAX_WORDFENCE_V3_NOTICE_PARTIES
                && evaluation_notices_are_valid
                && evaluation.record_reference.as_deref() == expected_record_reference
                && (!has_defiant_notice
                    || evaluation
                        .record_reference
                        .as_deref()
                        .is_some_and(is_wordfence_vulnerability_reference))
                && (evaluation.cve_link.is_none() || evaluation.cve.is_some())
                && evaluation
                    .affected_ranges
                    .iter()
                    .all(|range| range.is_valid(expanded_source_values))
                && external_range_labels_are_unique(&evaluation.affected_ranges)
                && evaluation.is_valid_interpretation(
                    explicit,
                    selected_profile,
                    validated_version.flatten(),
                    identity_mapping,
                )
                && evaluation.execution.exploit_execution == "not_performed"
                && evaluation.execution.impact_validation == "not_performed"
        });
        let mut limitation_ids = std::collections::BTreeSet::new();
        let limitations_are_valid = if source_identity {
            self.identity_limitations
                .as_ref()
                .is_some_and(|limitations| {
                    limitations.iter().all(|limitation| {
                        let source_association_base_is_unique =
                            source_association_base_ids.insert((
                                limitation.key.source_namespace,
                                limitation.key.upstream_id.as_str(),
                                limitation.key.source_component.kind,
                                limitation.key.source_component.slug.as_str(),
                            ));
                        limitation.is_valid(
                            self.source_namespace,
                            &notices_by_id,
                            &mut referenced_notices,
                            collection_limit,
                            expanded_source_values,
                        ) && (expanded_source_values || source_association_base_is_unique)
                            && limitation_ids.insert((
                                limitation.key.source_namespace,
                                limitation.key.upstream_id.as_str(),
                                limitation.key.source_component.kind,
                                limitation.key.source_component.slug.as_str(),
                                limitation.key.source_association_fingerprint.as_str(),
                            ))
                    }) && limitations.windows(2).all(|pair| {
                        (
                            pair[0].key.source_namespace,
                            pair[0].key.upstream_id.as_str(),
                            pair[0].key.source_component.kind,
                            pair[0].key.source_component.slug.as_str(),
                            pair[0].key.source_association_fingerprint.as_str(),
                        ) < (
                            pair[1].key.source_namespace,
                            pair[1].key.upstream_id.as_str(),
                            pair[1].key.source_component.kind,
                            pair[1].key.source_component.slug.as_str(),
                            pair[1].key.source_association_fingerprint.as_str(),
                        )
                    })
                })
        } else {
            self.identity_limitations.is_none()
        };
        evaluations_are_valid
            && limitations_are_valid
            && self
                .counts
                .selected_identity_counts_are_valid(selected_identity_counts)
            && self.counts.matches_evaluations(&self.evaluations, explicit)
            && referenced_notices == notices_by_id.keys().map(|id| (*id).to_owned()).collect()
            && self.evaluations.windows(2).all(|pair| {
                (
                    pair[0].key.source_namespace.as_str(),
                    pair[0].key.upstream_id.as_str(),
                    pair[0].key.component.kind,
                    pair[0].key.component.slug.as_str(),
                    pair[0]
                        .key
                        .source_component
                        .as_ref()
                        .map_or(pair[0].key.component.kind, |source| source.kind),
                    pair[0]
                        .key
                        .source_component
                        .as_ref()
                        .map_or(pair[0].key.component.slug.as_str(), |source| {
                            source.slug.as_str()
                        }),
                    pair[0].key.source_association_fingerprint.as_deref(),
                ) < (
                    pair[1].key.source_namespace.as_str(),
                    pair[1].key.upstream_id.as_str(),
                    pair[1].key.component.kind,
                    pair[1].key.component.slug.as_str(),
                    pair[1]
                        .key
                        .source_component
                        .as_ref()
                        .map_or(pair[1].key.component.kind, |source| source.kind),
                    pair[1]
                        .key
                        .source_component
                        .as_ref()
                        .map_or(pair[1].key.component.slug.as_str(), |source| {
                            source.slug.as_str()
                        }),
                    pair[1].key.source_association_fingerprint.as_deref(),
                )
            })
    }
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
impl WordPressExternalIdentityLimitationDocument {
    fn is_valid(
        &self,
        namespace: &str,
        notices: &std::collections::BTreeMap<&str, &WordPressExternalNoticeDocument>,
        referenced_notices: &mut std::collections::BTreeSet<String>,
        collection_limit: usize,
        expanded_source_values: bool,
    ) -> bool {
        let expected_record_reference = wordpress_external_record_reference(&self.references);
        let mut local_notices = std::collections::BTreeSet::new();
        let notice_ids_are_valid = self.notice_ids.iter().all(|id| {
            if notices.contains_key(id.as_str()) && local_notices.insert(id.as_str()) {
                referenced_notices.insert(id.clone());
                true
            } else {
                false
            }
        });
        let has_defiant_notice = self.notice_ids.iter().any(|id| {
            notices
                .get(id.as_str())
                .is_some_and(|notice| notice.party == "defiant")
        });
        self.key.source_namespace == namespace
            && valid_lowercase_uuid(&self.key.upstream_id)
            && valid_prefixed_lowercase_sha256(
                &self.key.source_association_fingerprint,
                "wordfence-source-association-sha256:",
            )
            && valid_wordfence_raw_source_identity(&self.key.source_component)
            && !wordfence_raw_source_identity_can_map(&self.key.source_component)
            && self.identity_resolution == "canonical_identity_unavailable"
            && !self.title.is_empty()
            && self.title.len() <= 1_024
            && !self.display_name.is_empty()
            && self.display_name.len() <= 1_024
            && self.references.len() <= crate::wordpress_review::MAX_WORDFENCE_V3_REFERENCES
            && self.record_reference.as_deref() == expected_record_reference
            && (!has_defiant_notice
                || self
                    .record_reference
                    .as_deref()
                    .is_some_and(is_wordfence_vulnerability_reference))
            && self.affected_ranges.len() <= collection_limit
            && self
                .affected_ranges
                .iter()
                .all(|range| range.is_valid(expanded_source_values))
            && external_range_labels_are_unique(&self.affected_ranges)
            && self.range_evaluations.len() == self.affected_ranges.len()
            && self.range_evaluations.iter().all(|range| {
                range.relation == "not_evaluated"
                    && range.reason == "canonical_identity_unavailable"
            })
            && self.source_patched_versions.len() <= collection_limit
            && external_source_versions_are_valid(
                &self.source_patched_versions,
                expanded_source_values,
            )
            && self.source_remediation.len()
                <= crate::wordpress_review::MAX_WORDPRESS_REMEDIATION_BYTES
            && self.notice_ids.len() <= crate::wordpress_review::MAX_WORDFENCE_V3_NOTICE_PARTIES
            && notice_ids_are_valid
            && self.version_relation == "not_evaluated"
            && self.version_relation_reason == "canonical_identity_unavailable"
            && self.applicability == "indeterminate"
            && self.execution.exploit_execution == "not_performed"
            && self.execution.impact_validation == "not_performed"
    }
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
impl WordPressExternalCountsDocument {
    fn selected_identity_counts_are_valid(&self, selected: [usize; 3]) -> bool {
        match (
            self.exact_identity_associations,
            self.candidate_identity_associations,
            self.ambiguous_identity_associations,
            self.unresolved_identity_associations,
        ) {
            (None, None, None, None) => {
                selected[0] == self.selected_associations && selected[1] == 0 && selected[2] == 0
            },
            (Some(exact), Some(candidate), Some(ambiguous), Some(_)) => {
                selected[0] <= exact
                    && selected[1] <= candidate
                    && selected[2] <= ambiguous
                    && selected
                        .iter()
                        .try_fold(0_usize, |total, count| total.checked_add(*count))
                        == Some(self.selected_associations)
            },
            _ => false,
        }
    }

    fn is_valid(&self, explicit: bool) -> bool {
        let extended = [
            self.within_associations,
            self.outside_associations,
            self.indeterminate_associations,
            self.selected_ranges,
            self.evaluated_ranges,
            self.containing_ranges,
            self.noncontaining_ranges,
            self.unsupported_ranges,
            self.invalid_ranges,
            self.not_evaluated_ranges,
            self.partial_range_coverage_associations,
        ];
        if !explicit {
            return extended.iter().all(Option::is_none)
                && self.evaluable_associations == 0
                && self.unsupported_associations == self.selected_associations;
        }
        let [Some(within), Some(outside), Some(indeterminate), Some(selected_ranges), Some(evaluated_ranges), Some(containing), Some(noncontaining), Some(unsupported_ranges), Some(invalid_ranges), Some(not_evaluated_ranges), Some(partial)] =
            extended
        else {
            return false;
        };
        within
            .checked_add(outside)
            .is_some_and(|value| value == self.evaluable_associations)
            && self.unsupported_associations == indeterminate
            && self
                .evaluable_associations
                .checked_add(indeterminate)
                .is_some_and(|value| value == self.selected_associations)
            && containing
                .checked_add(noncontaining)
                .is_some_and(|value| value == evaluated_ranges)
            && evaluated_ranges
                .checked_add(unsupported_ranges)
                .and_then(|value| value.checked_add(invalid_ranges))
                .and_then(|value| value.checked_add(not_evaluated_ranges))
                .is_some_and(|value| value == selected_ranges)
            && partial <= within
    }

    fn matches_evaluations(
        &self,
        evaluations: &[WordPressExternalEvaluationDocument],
        explicit: bool,
    ) -> bool {
        if !explicit {
            return true;
        }
        let mut within = 0_usize;
        let mut outside = 0_usize;
        let mut indeterminate = 0_usize;
        let mut containing = 0_usize;
        let mut noncontaining = 0_usize;
        let mut unsupported = 0_usize;
        let mut invalid = 0_usize;
        let mut not_evaluated = 0_usize;
        let mut partial = 0_usize;
        for evaluation in evaluations {
            match evaluation.version_relation {
                "within_supported_range_under_selected_policy" => within += 1,
                "outside_declared_ranges_under_selected_policy" => outside += 1,
                "indeterminate" => indeterminate += 1,
                _ => return false,
            }
            if evaluation.version_relation_reason == Some("containing_range_with_partial_coverage")
            {
                partial += 1;
            }
            let Some(ranges) = &evaluation.range_evaluations else {
                return false;
            };
            for range in ranges {
                match range.relation {
                    "contains" => containing += 1,
                    "does_not_contain" => noncontaining += 1,
                    "unsupported" => unsupported += 1,
                    "invalid_under_profile" => invalid += 1,
                    "not_evaluated" => not_evaluated += 1,
                    _ => return false,
                }
            }
        }
        self.within_associations == Some(within)
            && self.outside_associations == Some(outside)
            && self.indeterminate_associations == Some(indeterminate)
            && self.selected_ranges
                == containing
                    .checked_add(noncontaining)
                    .and_then(|value| value.checked_add(unsupported))
                    .and_then(|value| value.checked_add(invalid))
                    .and_then(|value| value.checked_add(not_evaluated))
            && self.containing_ranges == Some(containing)
            && self.noncontaining_ranges == Some(noncontaining)
            && self.unsupported_ranges == Some(unsupported)
            && self.invalid_ranges == Some(invalid)
            && self.not_evaluated_ranges == Some(not_evaluated)
            && self.partial_range_coverage_associations == Some(partial)
    }
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
impl WordPressExternalEvaluationDocument {
    fn is_valid_interpretation(
        &self,
        explicit: bool,
        selected_profile: Option<&str>,
        selected_version: Option<&crate::wordpress_version::ProfiledVersionKey>,
        identity_mapping: WordfenceV3IdentityMapping,
    ) -> bool {
        if !explicit {
            return self.range_evaluations.is_none()
                && self.version_relation == "source_comparison_semantics_unresolved"
                && self.version_relation_reason.is_none()
                && self.applicability == "indeterminate_unsupported";
        }
        let Some(ranges) = &self.range_evaluations else {
            return false;
        };
        if ranges.len() != self.affected_ranges.len()
            || !ranges
                .iter()
                .all(WordPressExternalRangeEvaluationDocument::is_valid)
        {
            return false;
        }
        let Some(profile) = selected_profile else {
            return false;
        };
        if identity_mapping != WordfenceV3IdentityMapping::Exact {
            let expected_reason = match identity_mapping {
                WordfenceV3IdentityMapping::Exact => return false,
                WordfenceV3IdentityMapping::AsciiCaseFoldCandidate => "identity_mapping_candidate",
                WordfenceV3IdentityMapping::AsciiCaseFoldAmbiguous => "identity_mapping_ambiguous",
            };
            return selected_version.is_none()
                && self.version_evidence_resolution.semantic_status.is_none()
                && self.version_evidence_resolution.semantic_reason.is_none()
                && ranges.iter().all(|range| {
                    range.relation == "not_evaluated" && range.reason == expected_reason
                })
                && self.version_relation == "indeterminate"
                && self.version_relation_reason == Some(expected_reason)
                && self.applicability == "indeterminate";
        }
        let semantic_status = self.version_evidence_resolution.semantic_status;
        if !ranges
            .iter()
            .zip(&self.affected_ranges)
            .all(|(rendered, source)| {
                expected_external_range_interpretation(
                    source,
                    profile,
                    semantic_status,
                    selected_version,
                ) == Some((rendered.relation, rendered.reason))
            })
        {
            return false;
        }
        let contains = ranges.iter().any(|range| range.relation == "contains");
        let unsupported = ranges.iter().any(|range| range.relation == "unsupported");
        let invalid = ranges
            .iter()
            .any(|range| range.relation == "invalid_under_profile");
        let source_patched_version_conflict = external_patched_version_conflicts(
            &self.source_patched_versions,
            &self.affected_ranges,
            profile,
        );
        let all_outside = !ranges.is_empty()
            && ranges
                .iter()
                .all(|range| range.relation == "does_not_contain");
        let semantic_status = self.version_evidence_resolution.semantic_status;
        match (
            self.version_relation,
            self.version_relation_reason,
            self.applicability,
        ) {
            (
                "within_supported_range_under_selected_policy",
                Some("containing_range"),
                "version_match_under_selected_policy",
            ) => {
                semantic_status == Some("supported_equivalent")
                    && contains
                    && !unsupported
                    && !invalid
                    && !source_patched_version_conflict
            },
            (
                "within_supported_range_under_selected_policy",
                Some("containing_range_with_partial_coverage"),
                "version_match_under_selected_policy",
            ) => {
                semantic_status == Some("supported_equivalent")
                    && contains
                    && unsupported
                    && !invalid
                    && !source_patched_version_conflict
            },
            (
                "outside_declared_ranges_under_selected_policy",
                Some("all_ranges_outside"),
                "no_version_match_under_selected_policy",
            ) => {
                semantic_status == Some("supported_equivalent")
                    && all_outside
                    && !source_patched_version_conflict
            },
            ("indeterminate", Some("invalid_affected_range"), "indeterminate") => invalid,
            (
                "indeterminate",
                Some("source_patched_version_within_affected_range"),
                "indeterminate",
            ) => !invalid && source_patched_version_conflict,
            ("indeterminate", Some("missing_version_evidence"), "indeterminate") => {
                semantic_status == Some("missing") && !invalid && !source_patched_version_conflict
            },
            ("indeterminate", Some("conflicting_version_evidence"), "indeterminate") => {
                semantic_status == Some("conflicting")
                    && !invalid
                    && !source_patched_version_conflict
            },
            ("indeterminate", Some("unsupported_version_evidence"), "indeterminate") => {
                semantic_status == Some("unsupported")
                    && !invalid
                    && !source_patched_version_conflict
            },
            ("indeterminate", Some("missing_affected_ranges"), "indeterminate") => {
                semantic_status == Some("supported_equivalent")
                    && ranges.is_empty()
                    && !source_patched_version_conflict
            },
            ("indeterminate", Some("unsupported_affected_range"), "indeterminate") => {
                semantic_status == Some("supported_equivalent")
                    && unsupported
                    && !contains
                    && !invalid
                    && !source_patched_version_conflict
            },
            _ => false,
        }
    }
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
impl WordPressExternalRangeEvaluationDocument {
    fn is_valid(&self) -> bool {
        matches!(
            (self.relation, self.reason),
            ("contains", "selected_version_within_bounds")
                | ("does_not_contain", "selected_version_outside_bounds")
                | ("not_evaluated", "missing_version_evidence")
                | ("not_evaluated", "conflicting_version_evidence")
                | ("not_evaluated", "unsupported_version_evidence")
                | ("not_evaluated", "identity_mapping_candidate")
                | ("not_evaluated", "identity_mapping_ambiguous")
                | ("unsupported", "unsupported_lower_bound")
                | ("unsupported", "unsupported_upper_bound")
                | ("unsupported", "unsupported_both_bounds")
                | ("invalid_under_profile", "reversed_bounds")
                | ("invalid_under_profile", "empty_exclusive_interval")
        )
    }
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
fn wordpress_external_source_counts_are_valid(
    parsed_records: usize,
    software_associations: usize,
) -> bool {
    match parsed_records {
        0 => software_associations == 0,
        count => {
            software_associations >= count
                && count
                    .checked_mul(MAX_WORDFENCE_V3_SOFTWARE_PER_RECORD)
                    .is_some_and(|maximum| software_associations <= maximum)
        },
    }
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
fn external_version_evidence_resolution_is_valid<'a>(
    resolution: &WordPressExternalVersionEvidenceResolutionDocument,
    validation: &'a WordPressExternalComponentValidation<'_>,
) -> Option<Option<&'a crate::wordpress_version::ProfiledVersionKey>> {
    (resolution.evidence_row_count == validation.evidence_row_count
        && resolution.distinct_spelling_count == validation.distinct_spelling_count
        && resolution.status == validation.evidence_status
        && resolution.semantic_status == validation.semantic_status
        && resolution.semantic_reason == validation.semantic_reason)
        .then_some(validation.selected_version.as_ref())
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
fn external_component_validation<'a>(
    component: &'a WordPressComponentDocument,
    selected_profile: Option<&str>,
) -> Option<WordPressExternalComponentValidation<'a>> {
    let distinct_spelling_count = component
        .versions
        .iter()
        .map(|version| version.value.as_str())
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    let evidence_row_count = component.versions.len();
    let evidence_status =
        wordpress_external_version_evidence_status(evidence_row_count, distinct_spelling_count)?;
    let (semantic_status, semantic_reason, selected_version) = match selected_profile {
        None => (None, None, None),
        Some(profile) => {
            let (status, reason, selected) = external_semantic_resolution(component, profile)?;
            (Some(status), Some(reason), selected)
        },
    };
    Some(WordPressExternalComponentValidation {
        component,
        evidence_status,
        evidence_row_count,
        distinct_spelling_count,
        semantic_status,
        semantic_reason,
        selected_version,
    })
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
fn external_semantic_resolution(
    component: &WordPressComponentDocument,
    profile: &str,
) -> Option<(
    &'static str,
    &'static str,
    Option<crate::wordpress_version::ProfiledVersionKey>,
)> {
    let profile = match profile {
        "numeric-dotted/v1" => WordPressComparisonProfile::NumericDottedV1,
        "php-release-subset/v1" => WordPressComparisonProfile::PhpReleaseSubsetV1,
        _ => return None,
    };
    if component.versions.is_empty() {
        return Some(("missing", "no_version_evidence", None));
    }
    let mut selected = None::<crate::wordpress_version::ProfiledVersionKey>;
    let mut conflicting = false;
    let mut unsupported = false;
    for evidence in &component.versions {
        match crate::wordpress_version::ProfiledVersionKey::parse(profile, &evidence.value) {
            Ok(version) => {
                if selected.as_ref().is_some_and(|selected| {
                    selected.compare(&version).ok() != Some(std::cmp::Ordering::Equal)
                }) {
                    conflicting = true;
                } else if selected.is_none() {
                    selected = Some(version);
                }
            },
            Err(_) => unsupported = true,
        }
    }
    if conflicting {
        Some(("conflicting", "conflicting_version_evidence", None))
    } else if unsupported || selected.is_none() {
        Some(("unsupported", "unsupported_version_evidence", None))
    } else if component.versions.len() == 1 {
        Some(("supported_equivalent", "single_supported_version", selected))
    } else {
        Some((
            "supported_equivalent",
            "equivalent_supported_versions",
            selected,
        ))
    }
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
fn expected_external_range_interpretation(
    range: &WordPressExternalRangeDocument,
    profile: &str,
    semantic_status: Option<&str>,
    selected_version: Option<&crate::wordpress_version::ProfiledVersionKey>,
) -> Option<(&'static str, &'static str)> {
    let profile = match profile {
        "numeric-dotted/v1" => WordPressComparisonProfile::NumericDottedV1,
        "php-release-subset/v1" => WordPressComparisonProfile::PhpReleaseSubsetV1,
        _ => return None,
    };
    let lower = reporting_external_range_endpoint(
        range.from_kind,
        &range.from_version,
        range.from_inclusive,
        profile,
    );
    let upper = reporting_external_range_endpoint(
        range.to_kind,
        &range.to_version,
        range.to_inclusive,
        profile,
    );
    let (lower, upper) = match (lower, upper) {
        (Err(()), Err(())) => return Some(("unsupported", "unsupported_both_bounds")),
        (Err(()), Ok(_)) => return Some(("unsupported", "unsupported_lower_bound")),
        (Ok(_), Err(())) => return Some(("unsupported", "unsupported_upper_bound")),
        (Ok(lower), Ok(upper)) => (lower, upper),
    };
    if let (Some((lower, lower_inclusive)), Some((upper, upper_inclusive))) = (&lower, &upper) {
        match lower.compare(upper).ok()? {
            std::cmp::Ordering::Greater => {
                return Some(("invalid_under_profile", "reversed_bounds"));
            },
            std::cmp::Ordering::Equal if !(*lower_inclusive && *upper_inclusive) => {
                return Some(("invalid_under_profile", "empty_exclusive_interval"));
            },
            std::cmp::Ordering::Less | std::cmp::Ordering::Equal => {},
        }
    }
    let Some(selected) = selected_version else {
        return match semantic_status {
            Some("missing") => Some(("not_evaluated", "missing_version_evidence")),
            Some("conflicting") => Some(("not_evaluated", "conflicting_version_evidence")),
            Some("unsupported") => Some(("not_evaluated", "unsupported_version_evidence")),
            _ => None,
        };
    };
    if semantic_status != Some("supported_equivalent") {
        return None;
    }
    let above_lower = lower.as_ref().is_none_or(|(lower, inclusive)| {
        lower.compare(selected).ok().is_some_and(|ordering| {
            ordering == std::cmp::Ordering::Less
                || (ordering == std::cmp::Ordering::Equal && *inclusive)
        })
    });
    let below_upper = upper.as_ref().is_none_or(|(upper, inclusive)| {
        selected.compare(upper).ok().is_some_and(|ordering| {
            ordering == std::cmp::Ordering::Less
                || (ordering == std::cmp::Ordering::Equal && *inclusive)
        })
    });
    Some(if above_lower && below_upper {
        ("contains", "selected_version_within_bounds")
    } else {
        ("does_not_contain", "selected_version_outside_bounds")
    })
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
fn reporting_external_range_endpoint(
    kind: &str,
    value: &str,
    inclusive: bool,
    profile: WordPressComparisonProfile,
) -> Result<Option<(crate::wordpress_version::ProfiledVersionKey, bool)>, ()> {
    match kind {
        "any" if value == "*" => Ok(None),
        "declared" if value != "*" => {
            crate::wordpress_version::ProfiledVersionKey::parse(profile, value)
                .map(|version| Some((version, inclusive)))
                .map_err(|_| ())
        },
        _ => Err(()),
    }
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
fn external_patched_version_conflicts(
    patched_versions: &[String],
    ranges: &[WordPressExternalRangeDocument],
    profile: &str,
) -> bool {
    let profile = match profile {
        "numeric-dotted/v1" => WordPressComparisonProfile::NumericDottedV1,
        "php-release-subset/v1" => WordPressComparisonProfile::PhpReleaseSubsetV1,
        _ => return false,
    };
    patched_versions.iter().any(|declared| {
        crate::wordpress_version::ProfiledVersionKey::parse(profile, declared)
            .ok()
            .is_some_and(|version| {
                ranges.iter().any(|range| {
                    expected_external_range_interpretation(
                        range,
                        profile.id(),
                        Some("supported_equivalent"),
                        Some(&version),
                    )
                    .is_some_and(|(relation, _)| relation == "contains")
                })
            })
    })
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
impl WordPressExternalRangeDocument {
    fn is_valid(&self, expanded_source_values: bool) -> bool {
        external_range_value_is_valid(self.from_kind, &self.from_version, expanded_source_values)
            && external_range_value_is_valid(self.to_kind, &self.to_version, expanded_source_values)
    }
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
fn external_range_labels_are_unique(ranges: &[WordPressExternalRangeDocument]) -> bool {
    let mut labels = std::collections::BTreeSet::new();
    ranges
        .iter()
        .all(|range| labels.insert(range.label.as_str()))
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
fn external_range_value_is_valid(kind: &str, value: &str, expanded_source_values: bool) -> bool {
    match kind {
        "any" => value == "*",
        "declared" => external_source_version_is_valid(value, expanded_source_values),
        _ => false,
    }
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
fn external_source_versions_are_valid(values: &[String], expanded_source_values: bool) -> bool {
    let mut unique = std::collections::BTreeSet::new();
    values.iter().all(|value| {
        external_source_version_is_valid(value, expanded_source_values)
            && unique.insert(value.as_str())
    })
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
fn external_source_version_is_valid(value: &str, expanded_source_values: bool) -> bool {
    if !expanded_source_values {
        return valid_inventory_version(value) && value != "*";
    }
    !value.is_empty()
        && value.len() <= crate::wordpress_review::MAX_WORDPRESS_VERSION_BYTES
        && value != "*"
        && !value.chars().any(char::is_control)
        && !value.chars().next().is_some_and(char::is_whitespace)
        && !value.chars().next_back().is_some_and(char::is_whitespace)
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
fn external_researchers_are_valid(values: &[String], expanded_source_values: bool) -> bool {
    if values.len() > crate::wordpress_review::MAX_WORDFENCE_V3_RESEARCHERS {
        return false;
    }
    let mut unique = std::collections::BTreeSet::new();
    values.iter().all(|value| {
        !value.is_empty()
            && value.len() <= crate::wordpress_review::MAX_WORDFENCE_V3_RESEARCHER_BYTES
            && !value
                .chars()
                .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
            && (expanded_source_values || unique.insert(value.as_str()))
    })
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
fn valid_prefixed_lowercase_sha256(value: &str, prefix: &str) -> bool {
    value
        .strip_prefix(prefix)
        .is_some_and(valid_lowercase_sha256)
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
fn valid_lowercase_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
        })
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
impl WordPressInventoryImportDocument {
    fn is_valid(&self, components: &[WordPressComponentDocument]) -> bool {
        let mut classes = std::collections::BTreeSet::new();
        let mut total_bytes = 0_usize;
        for input in &self.inputs {
            if !matches!(
                input.class,
                "wp_cli_plugins_json" | "wp_cli_themes_json" | "wp_cli_core_version_file"
            ) || !classes.insert(input.class)
                || input.byte_length == 0
                || (input.class == "wp_cli_core_version_file"
                    && input.byte_length > crate::wordpress_review::MAX_WORDPRESS_VERSION_BYTES + 2)
                || !valid_lowercase_sha256(&input.sha256)
            {
                return false;
            }
            let Some(next) = total_bytes.checked_add(input.byte_length) else {
                return false;
            };
            total_bytes = next;
        }
        let supplied = |class| classes.contains(class);
        if self.inputs.is_empty()
            || self.inputs.len() > 3
            || total_bytes > MAX_WORDPRESS_SAVED_INVENTORY_BYTES
            || (self.coverage.core == "supplied") != supplied("wp_cli_core_version_file")
            || (self.coverage.plugins == "supplied") != supplied("wp_cli_plugins_json")
            || (self.coverage.themes == "supplied") != supplied("wp_cli_themes_json")
            || !matches!(self.coverage.core, "supplied" | "not_supplied")
            || !matches!(self.coverage.plugins, "supplied" | "not_supplied")
            || !matches!(self.coverage.themes, "supplied" | "not_supplied")
        {
            return false;
        }

        let inventory_components = components
            .iter()
            .filter(|component| component.inventory_status.is_some())
            .count();
        if self.component_count != inventory_components
            || self
                .component_count
                .checked_add(self.limitations.len())
                .is_none_or(|count| {
                    count > crate::wordpress_review::MAX_WORDPRESS_CONTEXT_COMPONENTS
                })
            || components
                .iter()
                .any(|component| !component.inventory_status_is_valid(&self.coverage))
        {
            return false;
        }

        let mut limitations = std::collections::BTreeSet::new();
        self.limitations.iter().all(|limitation| {
            self.coverage.plugins == "supplied"
                && limitation.status == "drop_in"
                && limitation.reason == "drop_in_identity_is_not_catalog_slug"
                && valid_inventory_label(&limitation.declared_name)
                && limitation
                    .version
                    .as_deref()
                    .is_none_or(valid_inventory_version)
                && limitations.insert(limitation.declared_name.as_str())
        })
    }
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
impl WordPressComponentDocument {
    fn inventory_status_is_valid(&self, coverage: &WordPressInventoryCoverageDocument) -> bool {
        let operator_supplied = self.identity_sources.contains(&"operator_context");
        let Some(status) = self.inventory_status else {
            return !operator_supplied;
        };
        if !operator_supplied {
            return false;
        }
        match status {
            "core_version_supplied" => {
                self.identity.kind == "core"
                    && self.identity.slug == "wordpress"
                    && self.activation.is_none()
                    && coverage.core == "supplied"
            },
            "active" => {
                ((self.identity.kind == "plugin" && coverage.plugins == "supplied")
                    || (self.identity.kind == "theme" && coverage.themes == "supplied"))
                    && self.activation == Some("active")
            },
            "inactive" => {
                ((self.identity.kind == "plugin" && coverage.plugins == "supplied")
                    || (self.identity.kind == "theme" && coverage.themes == "supplied"))
                    && self.activation == Some("inactive")
            },
            "active_network" => {
                self.identity.kind == "plugin"
                    && coverage.plugins == "supplied"
                    && self.activation == Some("network_active")
            },
            "must_use" => {
                self.identity.kind == "plugin"
                    && coverage.plugins == "supplied"
                    && self.activation.is_none()
            },
            "parent" => {
                self.identity.kind == "theme"
                    && coverage.themes == "supplied"
                    && self.activation.is_none()
            },
            _ => false,
        }
    }
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
fn valid_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
fn valid_inventory_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= crate::wordpress_review::MAX_WORDPRESS_SLUG_BYTES
        && !matches!(value, "." | "..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
fn valid_inventory_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= crate::wordpress_review::MAX_WORDPRESS_VERSION_BYTES
        && !value
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
impl WordPressAdvisoryDocument {
    fn profile_fields_are_valid(&self, profiled: bool) -> bool {
        if !profiled {
            return self.comparison_profile.is_none()
                && self.version_resolution.is_none()
                && self.version_resolution_reason.is_none();
        }
        let Some(profile) = self.comparison_profile else {
            return false;
        };
        if !matches!(profile, "numeric-dotted/v1" | "php-release-subset/v1") {
            return false;
        }
        matches!(
            (self.version_resolution, self.version_resolution_reason),
            (Some("missing"), Some("no_version_evidence"))
                | (
                    Some("supported_equivalent"),
                    Some("single_supported_version" | "equivalent_supported_versions")
                )
                | (Some("conflicting"), Some("conflicting_version_evidence"))
                | (Some("unsupported"), Some("unsupported_version_evidence"))
        )
    }
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
fn wordpress_component_identity(
    identity: &crate::wordpress_review::WordPressComponentIdentity,
) -> WordPressComponentIdentityDocument {
    WordPressComponentIdentityDocument {
        kind: wordpress_component_kind(identity.kind()),
        slug: identity.slug().to_owned(),
    }
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
fn wordpress_prerequisite(
    prerequisite: &WordPressPrerequisite,
    outcome: WordPressPrerequisiteOutcome,
) -> WordPressPrerequisiteDocument {
    let (kind, expected, patch_id) = match prerequisite {
        WordPressPrerequisite::HostingOs { equals } => {
            ("hosting_os", wordpress_hosting_os(*equals).to_owned(), None)
        },
        WordPressPrerequisite::Multisite { equals } => {
            ("multisite", wordpress_multisite(*equals).to_owned(), None)
        },
        WordPressPrerequisite::Activation { equals } => {
            ("activation", wordpress_activation(*equals).to_owned(), None)
        },
        WordPressPrerequisite::Patch { id, equals } => (
            "patch",
            wordpress_patch(*equals).to_owned(),
            Some(id.clone()),
        ),
        WordPressPrerequisite::Unsupported { name } => ("unsupported", name.clone(), None),
    };
    WordPressPrerequisiteDocument {
        kind,
        expected,
        patch_id,
        outcome: wordpress_prerequisite_outcome(outcome),
    }
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
const fn wordpress_component_kind(kind: WordPressComponentKind) -> &'static str {
    match kind {
        WordPressComponentKind::Core => "core",
        WordPressComponentKind::Plugin => "plugin",
        WordPressComponentKind::Theme => "theme",
    }
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
const fn wordpress_catalog_status(status: WordPressCatalogStatus) -> &'static str {
    match status {
        WordPressCatalogStatus::CatalogNotSupplied => "catalogue_not_supplied",
        WordPressCatalogStatus::Evaluated => "evaluated",
    }
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
const fn wordpress_evidence_source(source: WordPressEvidenceSource) -> &'static str {
    match source {
        WordPressEvidenceSource::GeneratorMetadata => "generator_metadata",
        WordPressEvidenceSource::SameOriginAssetPath => "same_origin_asset_path",
        WordPressEvidenceSource::ThemeStylesheetDeclaration => "theme_stylesheet_declaration",
        WordPressEvidenceSource::OperatorContext => "operator_context",
    }
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
const fn wordpress_confidence(confidence: WordPressEvidenceConfidence) -> &'static str {
    match confidence {
        WordPressEvidenceConfidence::PublicDeclaration => "public_declaration",
        WordPressEvidenceConfidence::StructuralHint => "structural_hint",
        WordPressEvidenceConfidence::OperatorAssertion => "operator_assertion",
    }
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
const fn wordpress_evidence_class(class: WordPressComponentEvidenceClass) -> &'static str {
    match class {
        WordPressComponentEvidenceClass::ObservedHint => "observed_hint",
        WordPressComponentEvidenceClass::OperatorSupplied => "operator_supplied",
        WordPressComponentEvidenceClass::Conflicting => "conflicting",
        WordPressComponentEvidenceClass::Unknown => "unknown",
    }
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
const fn wordpress_activation(state: WordPressActivationState) -> &'static str {
    match state {
        WordPressActivationState::Active => "active",
        WordPressActivationState::Inactive => "inactive",
        WordPressActivationState::NetworkActive => "network_active",
        WordPressActivationState::Unknown => "unknown",
    }
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
const fn wordpress_inventory_category_status(
    status: WordPressInventoryCategoryStatus,
) -> &'static str {
    match status {
        WordPressInventoryCategoryStatus::NotSupplied => "not_supplied",
        WordPressInventoryCategoryStatus::Supplied => "supplied",
    }
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
const fn wordpress_inventory_entry_status(status: WordPressInventoryEntryStatus) -> &'static str {
    match status {
        WordPressInventoryEntryStatus::CoreVersionSupplied => "core_version_supplied",
        WordPressInventoryEntryStatus::Active => "active",
        WordPressInventoryEntryStatus::Inactive => "inactive",
        WordPressInventoryEntryStatus::NetworkActive => "active_network",
        WordPressInventoryEntryStatus::MustUse => "must_use",
        WordPressInventoryEntryStatus::DropIn => "drop_in",
        WordPressInventoryEntryStatus::Parent => "parent",
    }
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
const fn wordpress_inventory_limitation_reason(
    reason: WordPressInventoryLimitationReason,
) -> &'static str {
    match reason {
        WordPressInventoryLimitationReason::DropInIdentityIsNotCatalogSlug => {
            "drop_in_identity_is_not_catalog_slug"
        },
    }
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
const fn wordpress_local_input_class(class: WordPressLocalInputClass) -> &'static str {
    match class {
        WordPressLocalInputClass::PluginsJson => "wp_cli_plugins_json",
        WordPressLocalInputClass::ThemesJson => "wp_cli_themes_json",
        WordPressLocalInputClass::CoreVersionFile => "wp_cli_core_version_file",
    }
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
fn lowercase_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
fn wordpress_external_review_document(
    review: &crate::wordpress_review::WordPressExternalReview,
) -> WordPressExternalReviewDocument {
    let counts = review.counts();
    let comparison_policy = wordpress_external_comparison_policy(review.comparison_policy());
    let explicit = review.comparison_profile().is_some();
    let source_identity = review.requires_audit_v6();
    WordPressExternalReviewDocument {
        source_namespace: review.source_namespace(),
        source_format: review.source_format(),
        mapping_revision: review.mapping_revision(),
        identity_mapping_policy: source_identity.then_some(review.identity_mapping_policy()),
        identity_source_assurance: source_identity.then_some(review.identity_source_assurance()),
        resource_policy: source_identity.then_some(review.resource_policy()),
        comparison_policy,
        comparison_profile: review
            .comparison_profile()
            .map(wordpress_comparison_profile),
        policy_selection: explicit.then_some("explicit_operator"),
        source_semantics_assurance: explicit.then_some("not_established"),
        input: WordPressExternalInputDocument {
            byte_length: review.byte_length(),
            sha256: lowercase_hex(review.sha256()),
            semantic_sha256: lowercase_hex(review.semantic_sha256()),
            accounted_retained_bytes: source_identity.then_some(review.retained_bytes()),
        },
        counts: WordPressExternalCountsDocument {
            parsed_records: counts.parsed_records(),
            software_associations: counts.software_associations(),
            exact_identity_associations: source_identity
                .then_some(counts.exact_identity_associations()),
            candidate_identity_associations: source_identity
                .then_some(counts.candidate_identity_associations()),
            ambiguous_identity_associations: source_identity
                .then_some(counts.ambiguous_identity_associations()),
            unresolved_identity_associations: source_identity
                .then_some(counts.unresolved_identity_associations()),
            projected_identity_limitations: source_identity
                .then_some(counts.projected_identity_limitations()),
            unprojected_identity_limitations: source_identity
                .then_some(counts.unprojected_identity_limitations()),
            selected_associations: counts.selected_associations(),
            evaluable_associations: counts.evaluable_associations(),
            unsupported_associations: counts.unsupported_associations(),
            excluded_associations: counts.excluded_associations(),
            mapped_unselected_associations: source_identity
                .then_some(counts.mapped_unselected_associations()),
            within_associations: explicit.then_some(counts.within_associations()),
            outside_associations: explicit.then_some(counts.outside_associations()),
            indeterminate_associations: explicit.then_some(counts.indeterminate_associations()),
            selected_ranges: explicit.then_some(counts.selected_ranges()),
            evaluated_ranges: explicit.then_some(counts.evaluated_ranges()),
            containing_ranges: explicit.then_some(counts.containing_ranges()),
            noncontaining_ranges: explicit.then_some(counts.noncontaining_ranges()),
            unsupported_ranges: explicit.then_some(counts.unsupported_ranges()),
            invalid_ranges: explicit.then_some(counts.invalid_ranges()),
            not_evaluated_ranges: explicit.then_some(counts.not_evaluated_ranges()),
            partial_range_coverage_associations: explicit
                .then_some(counts.partial_range_coverage_associations()),
        },
        notices: review
            .notices()
            .iter()
            .map(|notice| WordPressExternalNoticeDocument {
                id: notice.id().to_owned(),
                message: notice.message().to_owned(),
                party: notice.party().to_owned(),
                notice: notice.notice().to_owned(),
                license: notice.license().to_owned(),
                license_url: notice.license_url().to_owned(),
            })
            .collect(),
        evaluations: review
            .evaluations()
            .iter()
            .map(|evaluation| wordpress_external_evaluation_document(evaluation, source_identity))
            .collect(),
        identity_limitations: source_identity.then(|| {
            review
                .identity_limitations()
                .iter()
                .map(wordpress_external_identity_limitation_document)
                .collect()
        }),
    }
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
const fn wordpress_external_comparison_policy(
    policy: WordPressExternalComparisonPolicy,
) -> &'static str {
    match policy {
        WordPressExternalComparisonPolicy::WordfenceV3SourceSemanticsUnresolvedV1 => {
            "wordfence-v3/source-semantics-unresolved/v1"
        },
        WordPressExternalComparisonPolicy::TermivarWordfenceV3ExplicitInterpretationV1 => {
            "termivar.wordfence-v3-explicit-interpretation/v1"
        },
    }
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
fn external_identity_mapping_is_valid(
    evaluation: &WordPressExternalEvaluationDocument,
    source_identity: bool,
) -> Option<WordfenceV3IdentityMapping> {
    if !source_identity {
        return (evaluation.identity_mapping.is_none()
            && evaluation.identity_collision_raw_count.is_none()
            && evaluation.key.source_component.is_none())
        .then_some(WordfenceV3IdentityMapping::Exact);
    }

    let source = evaluation.key.source_component.as_ref()?;
    if !valid_wordfence_source_identity(source) {
        return None;
    }
    let mapping = match evaluation.identity_mapping? {
        "exact" => WordfenceV3IdentityMapping::Exact,
        "ascii_case_fold_candidate" => WordfenceV3IdentityMapping::AsciiCaseFoldCandidate,
        "ascii_case_fold_ambiguous" => WordfenceV3IdentityMapping::AsciiCaseFoldAmbiguous,
        _ => return None,
    };
    let canonical = &evaluation.key.component;
    let same_kind = source.kind == canonical.kind;
    let exact = same_kind && source.slug == canonical.slug;
    let case_fold = same_kind
        && source.slug != canonical.slug
        && source.slug.eq_ignore_ascii_case(&canonical.slug);
    match mapping {
        WordfenceV3IdentityMapping::Exact => {
            (exact && evaluation.identity_collision_raw_count.is_none()).then_some(mapping)
        },
        WordfenceV3IdentityMapping::AsciiCaseFoldCandidate => {
            (case_fold && evaluation.identity_collision_raw_count.is_none()).then_some(mapping)
        },
        WordfenceV3IdentityMapping::AsciiCaseFoldAmbiguous => evaluation
            .identity_collision_raw_count
            .is_some_and(|count| count >= 2)
            .then_some(mapping)
            .filter(|_| case_fold),
    }
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
fn valid_wordfence_source_identity(
    identity: &WordPressExternalSourceComponentIdentityDocument,
) -> bool {
    const MAX_SOURCE_SLUG_BYTES: usize = 128;
    matches!(identity.kind, "core" | "plugin" | "theme")
        && !identity.slug.is_empty()
        && identity.slug.len() <= MAX_SOURCE_SLUG_BYTES
        && !identity.slug.starts_with('-')
        && !identity.slug.ends_with('-')
        && !identity.slug.contains("--")
        && identity
            .slug
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
fn valid_wordfence_raw_source_identity(
    identity: &WordPressExternalSourceComponentIdentityDocument,
) -> bool {
    const MAX_SOURCE_SLUG_BYTES: usize = 128;
    matches!(identity.kind, "core" | "plugin" | "theme")
        && !identity.slug.is_empty()
        && identity.slug.len() <= MAX_SOURCE_SLUG_BYTES
        && identity.slug.is_ascii()
        && !identity.slug.bytes().any(|byte| byte.is_ascii_control())
        && identity
            .slug
            .bytes()
            .any(|byte| byte.is_ascii_alphanumeric())
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
fn wordfence_raw_source_identity_can_map(
    identity: &WordPressExternalSourceComponentIdentityDocument,
) -> bool {
    valid_wordfence_source_identity(identity)
        && identity.slug.len() <= crate::wordpress_review::MAX_WORDPRESS_SLUG_BYTES
        && match identity.kind {
            "core" => identity.slug.eq_ignore_ascii_case("wordpress"),
            "plugin" | "theme" => !identity.slug.eq_ignore_ascii_case("wordpress"),
            _ => false,
        }
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
fn wordpress_external_evaluation_document(
    evaluation: &crate::wordpress_review::WordPressExternalAdvisoryEvaluation,
    source_identity: bool,
) -> WordPressExternalEvaluationDocument {
    let key = evaluation.key();
    WordPressExternalEvaluationDocument {
        key: WordPressExternalEvaluationKeyDocument {
            source_namespace: key.source_namespace().to_owned(),
            upstream_id: key.upstream_id().to_owned(),
            component: wordpress_component_identity(key.component()),
            source_component: source_identity.then(|| {
                WordPressExternalSourceComponentIdentityDocument {
                    kind: wordpress_component_kind(key.source_component().kind()),
                    slug: key.source_component().slug().to_owned(),
                }
            }),
            source_association_fingerprint: source_identity.then(|| {
                format!(
                    "wordfence-source-association-sha256:{}",
                    lowercase_hex(key.source_association_sha256())
                )
            }),
        },
        identity_mapping: source_identity.then_some(evaluation.identity_mapping().as_str()),
        identity_collision_raw_count: if source_identity {
            evaluation.identity_collision_raw_count()
        } else {
            None
        },
        title: evaluation.title().to_owned(),
        display_name: evaluation.display_name().to_owned(),
        informational: evaluation.informational(),
        description: evaluation.description().to_owned(),
        references: evaluation.references().to_vec(),
        record_reference: wordpress_external_record_reference(evaluation.references())
            .map(str::to_owned),
        cwe: evaluation.cwe().map(|cwe| WordPressExternalCweDocument {
            id: cwe.id(),
            name: cwe.name().to_owned(),
            description: cwe.description().to_owned(),
        }),
        cvss: evaluation.cvss().map(|cvss| WordPressExternalCvssDocument {
            vector: cvss.vector().to_owned(),
            score: cvss.score().to_owned(),
            rating: wordpress_external_cvss_rating(cvss.rating()),
        }),
        cve: evaluation.cve().map(str::to_owned),
        cve_link: evaluation.cve_link().map(str::to_owned),
        researchers: evaluation.researchers().to_vec(),
        source_dates: WordPressExternalSourceDatesDocument {
            published: evaluation.published().map(str::to_owned),
            updated: evaluation.updated().map(str::to_owned),
        },
        affected_ranges: evaluation
            .affected_ranges()
            .iter()
            .map(|range| {
                let (from_kind, from_version) =
                    wordpress_external_range_value(range.from().value());
                let (to_kind, to_version) = wordpress_external_range_value(range.to().value());
                WordPressExternalRangeDocument {
                    label: range.label().to_owned(),
                    from_kind,
                    from_version,
                    from_inclusive: range.from().inclusive(),
                    to_kind,
                    to_version,
                    to_inclusive: range.to().inclusive(),
                }
            })
            .collect(),
        range_evaluations: evaluation.range_evaluations().map(|ranges| {
            ranges
                .iter()
                .map(|range| WordPressExternalRangeEvaluationDocument {
                    relation: wordpress_external_range_relation(range.relation()),
                    reason: wordpress_external_range_reason(range.reason()),
                })
                .collect()
        }),
        source_patched: evaluation.source_patched(),
        source_patched_versions: evaluation.source_patched_versions().to_vec(),
        source_remediation: evaluation.source_remediation().to_owned(),
        notice_ids: evaluation.notice_ids().to_vec(),
        component_evidence: wordpress_evidence_class(evaluation.component_evidence()),
        version_evidence_resolution: wordpress_external_version_evidence_resolution(
            evaluation.version_evidence_resolution(),
        ),
        version_relation: wordpress_external_version_relation(evaluation.version_relation()),
        version_relation_reason: evaluation.range_evaluations().map(|_| {
            wordpress_external_version_relation_reason(evaluation.version_relation_reason())
        }),
        applicability: wordpress_external_applicability(evaluation.applicability()),
        execution: WordPressExternalExecutionDocument {
            exploit_execution: wordpress_execution(evaluation.exploit_execution()),
            impact_validation: wordpress_execution(evaluation.impact_validation()),
        },
    }
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
fn wordpress_external_identity_limitation_document(
    limitation: &crate::wordpress_review::WordPressExternalIdentityLimitation,
) -> WordPressExternalIdentityLimitationDocument {
    let affected_ranges = limitation
        .affected_ranges()
        .iter()
        .map(wordpress_external_range_document)
        .collect::<Vec<_>>();
    WordPressExternalIdentityLimitationDocument {
        key: WordPressExternalIdentityLimitationKeyDocument {
            source_namespace: "wordfence-intelligence",
            upstream_id: limitation.upstream_id().to_owned(),
            source_component: WordPressExternalSourceComponentIdentityDocument {
                kind: wordpress_component_kind(limitation.source_component().kind()),
                slug: limitation.source_component().slug().to_owned(),
            },
            source_association_fingerprint: format!(
                "wordfence-source-association-sha256:{}",
                lowercase_hex(limitation.source_association_sha256())
            ),
        },
        identity_resolution: "canonical_identity_unavailable",
        title: limitation.title().to_owned(),
        display_name: limitation.display_name().to_owned(),
        references: limitation.references().to_vec(),
        record_reference: wordpress_external_record_reference(limitation.references())
            .map(str::to_owned),
        range_evaluations: affected_ranges
            .iter()
            .map(|_| WordPressExternalRangeEvaluationDocument {
                relation: "not_evaluated",
                reason: "canonical_identity_unavailable",
            })
            .collect(),
        affected_ranges,
        source_patched: limitation.source_patched(),
        source_patched_versions: limitation.source_patched_versions().to_vec(),
        source_remediation: limitation.source_remediation().to_owned(),
        notice_ids: limitation.notice_ids().to_vec(),
        version_relation: "not_evaluated",
        version_relation_reason: "canonical_identity_unavailable",
        applicability: "indeterminate",
        execution: WordPressExternalExecutionDocument {
            exploit_execution: "not_performed",
            impact_validation: "not_performed",
        },
    }
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
fn wordpress_external_range_document(
    range: &crate::wordpress_review::WordfenceV3AffectedRange,
) -> WordPressExternalRangeDocument {
    let (from_kind, from_version) = wordpress_external_range_value(range.from().value());
    let (to_kind, to_version) = wordpress_external_range_value(range.to().value());
    WordPressExternalRangeDocument {
        label: range.label().to_owned(),
        from_kind,
        from_version,
        from_inclusive: range.from().inclusive(),
        to_kind,
        to_version,
        to_inclusive: range.to().inclusive(),
    }
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
fn wordpress_external_record_reference(references: &[String]) -> Option<&str> {
    references
        .iter()
        .map(String::as_str)
        .filter(|reference| is_wordfence_vulnerability_reference(reference))
        .min()
        .or_else(|| {
            references
                .iter()
                .map(String::as_str)
                .filter(|reference| is_strict_https_reference(reference))
                .min()
        })
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
fn is_strict_https_reference(value: &str) -> bool {
    url::Url::parse(value).ok().is_some_and(|url| {
        url.scheme() == "https"
            && url.has_host()
            && url.username().is_empty()
            && url.password().is_none()
            && url.port().is_none()
            && url.as_str() == value
    })
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
fn is_wordfence_vulnerability_reference(value: &str) -> bool {
    const PREFIX: &str = "/threat-intel/vulnerabilities/";
    url::Url::parse(value).ok().is_some_and(|url| {
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

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
fn has_supported_wordfence_reference_query(url: &url::Url) -> bool {
    const MAX_SOURCE_VALUE_BYTES: usize = 64;
    // Keep this in lockstep with the strict Production import contract.
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

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
fn wordpress_external_version_evidence_resolution(
    resolution: &crate::wordpress_review::WordPressExternalVersionEvidenceResolution,
) -> WordPressExternalVersionEvidenceResolutionDocument {
    WordPressExternalVersionEvidenceResolutionDocument {
        status: match resolution.status() {
            WordPressExternalVersionEvidenceStatus::Missing => "missing",
            WordPressExternalVersionEvidenceStatus::SingleDeclaration => "single_declaration",
            WordPressExternalVersionEvidenceStatus::RepeatedExactDeclaration => {
                "repeated_exact_declaration"
            },
            WordPressExternalVersionEvidenceStatus::MultipleDistinctDeclarations => {
                "multiple_distinct_declarations"
            },
        },
        evidence_row_count: resolution.evidence_row_count(),
        distinct_spelling_count: resolution.distinct_spelling_count(),
        semantic_status: resolution
            .semantic_status()
            .map(wordpress_version_resolution),
        semantic_reason: resolution
            .semantic_reason()
            .map(wordpress_version_resolution_reason),
    }
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
const fn wordpress_external_version_evidence_status(
    evidence_row_count: usize,
    distinct_spelling_count: usize,
) -> Option<&'static str> {
    match (evidence_row_count, distinct_spelling_count) {
        (0, 0) => Some("missing"),
        (1, 1) => Some("single_declaration"),
        (count, 1) if count > 1 => Some("repeated_exact_declaration"),
        (count, distinct) if count > 1 && distinct > 1 && distinct <= count => {
            Some("multiple_distinct_declarations")
        },
        _ => None,
    }
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
fn wordpress_external_range_value(value: &WordfenceV3RangeValue) -> (&'static str, String) {
    match value {
        WordfenceV3RangeValue::Any => ("any", "*".to_owned()),
        WordfenceV3RangeValue::Declared(value) => ("declared", value.clone()),
    }
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
const fn wordpress_external_cvss_rating(rating: WordfenceV3CvssRating) -> &'static str {
    match rating {
        WordfenceV3CvssRating::None => "none",
        WordfenceV3CvssRating::Low => "low",
        WordfenceV3CvssRating::Medium => "medium",
        WordfenceV3CvssRating::High => "high",
        WordfenceV3CvssRating::Critical => "critical",
    }
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
const fn wordpress_external_version_relation(
    relation: WordPressExternalVersionRelation,
) -> &'static str {
    match relation {
        WordPressExternalVersionRelation::SourceComparisonSemanticsUnresolved => {
            "source_comparison_semantics_unresolved"
        },
        WordPressExternalVersionRelation::WithinSupportedRangeUnderSelectedPolicy => {
            "within_supported_range_under_selected_policy"
        },
        WordPressExternalVersionRelation::OutsideDeclaredRangesUnderSelectedPolicy => {
            "outside_declared_ranges_under_selected_policy"
        },
        WordPressExternalVersionRelation::Indeterminate => "indeterminate",
    }
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
const fn wordpress_external_version_relation_reason(
    reason: WordPressExternalVersionRelationReason,
) -> &'static str {
    match reason {
        WordPressExternalVersionRelationReason::SourceComparisonSemanticsUnresolved => {
            "source_comparison_semantics_unresolved"
        },
        WordPressExternalVersionRelationReason::ContainingRange => "containing_range",
        WordPressExternalVersionRelationReason::ContainingRangeWithPartialCoverage => {
            "containing_range_with_partial_coverage"
        },
        WordPressExternalVersionRelationReason::AllRangesOutside => "all_ranges_outside",
        WordPressExternalVersionRelationReason::MissingVersionEvidence => {
            "missing_version_evidence"
        },
        WordPressExternalVersionRelationReason::ConflictingVersionEvidence => {
            "conflicting_version_evidence"
        },
        WordPressExternalVersionRelationReason::UnsupportedVersionEvidence => {
            "unsupported_version_evidence"
        },
        WordPressExternalVersionRelationReason::MissingAffectedRanges => "missing_affected_ranges",
        WordPressExternalVersionRelationReason::UnsupportedAffectedRange => {
            "unsupported_affected_range"
        },
        WordPressExternalVersionRelationReason::InvalidAffectedRange => "invalid_affected_range",
        WordPressExternalVersionRelationReason::SourcePatchedVersionWithinAffectedRange => {
            "source_patched_version_within_affected_range"
        },
        WordPressExternalVersionRelationReason::IdentityMappingCandidate => {
            "identity_mapping_candidate"
        },
        WordPressExternalVersionRelationReason::IdentityMappingAmbiguous => {
            "identity_mapping_ambiguous"
        },
    }
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
const fn wordpress_external_range_relation(
    relation: WordPressExternalRangeRelation,
) -> &'static str {
    match relation {
        WordPressExternalRangeRelation::Contains => "contains",
        WordPressExternalRangeRelation::DoesNotContain => "does_not_contain",
        WordPressExternalRangeRelation::NotEvaluated => "not_evaluated",
        WordPressExternalRangeRelation::Unsupported => "unsupported",
        WordPressExternalRangeRelation::InvalidUnderProfile => "invalid_under_profile",
    }
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
const fn wordpress_external_range_reason(reason: WordPressExternalRangeReason) -> &'static str {
    match reason {
        WordPressExternalRangeReason::SelectedVersionWithinBounds => {
            "selected_version_within_bounds"
        },
        WordPressExternalRangeReason::SelectedVersionOutsideBounds => {
            "selected_version_outside_bounds"
        },
        WordPressExternalRangeReason::MissingVersionEvidence => "missing_version_evidence",
        WordPressExternalRangeReason::ConflictingVersionEvidence => "conflicting_version_evidence",
        WordPressExternalRangeReason::UnsupportedVersionEvidence => "unsupported_version_evidence",
        WordPressExternalRangeReason::UnsupportedLowerBound => "unsupported_lower_bound",
        WordPressExternalRangeReason::UnsupportedUpperBound => "unsupported_upper_bound",
        WordPressExternalRangeReason::UnsupportedBothBounds => "unsupported_both_bounds",
        WordPressExternalRangeReason::ReversedBounds => "reversed_bounds",
        WordPressExternalRangeReason::EmptyExclusiveInterval => "empty_exclusive_interval",
        WordPressExternalRangeReason::IdentityMappingCandidate => "identity_mapping_candidate",
        WordPressExternalRangeReason::IdentityMappingAmbiguous => "identity_mapping_ambiguous",
    }
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
const fn wordpress_external_applicability(
    applicability: WordPressExternalApplicability,
) -> &'static str {
    match applicability {
        WordPressExternalApplicability::IndeterminateUnsupported => "indeterminate_unsupported",
        WordPressExternalApplicability::VersionMatchUnderSelectedPolicy => {
            "version_match_under_selected_policy"
        },
        WordPressExternalApplicability::NoVersionMatchUnderSelectedPolicy => {
            "no_version_match_under_selected_policy"
        },
        WordPressExternalApplicability::Indeterminate => "indeterminate",
    }
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
const fn wordpress_hosting_os(os: WordPressHostingOs) -> &'static str {
    match os {
        WordPressHostingOs::Linux => "linux",
        WordPressHostingOs::Windows => "windows",
        WordPressHostingOs::Macos => "macos",
        WordPressHostingOs::Bsd => "bsd",
        WordPressHostingOs::Other => "other",
    }
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
const fn wordpress_multisite(state: WordPressMultisiteState) -> &'static str {
    match state {
        WordPressMultisiteState::Enabled => "enabled",
        WordPressMultisiteState::Disabled => "disabled",
    }
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
const fn wordpress_patch(state: WordPressPatchState) -> &'static str {
    match state {
        WordPressPatchState::Applied => "applied",
        WordPressPatchState::NotApplied => "not_applied",
        WordPressPatchState::Unknown => "unknown",
    }
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
const fn wordpress_version_relation(relation: WordPressVersionRelation) -> &'static str {
    match relation {
        WordPressVersionRelation::WithinDeclaredRange => "within_declared_range",
        WordPressVersionRelation::OutsideDeclaredRanges => "outside_declared_ranges",
        WordPressVersionRelation::Unknown => "unknown",
        WordPressVersionRelation::Unsupported => "unsupported",
    }
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
const fn wordpress_comparison_profile(profile: WordPressComparisonProfile) -> &'static str {
    match profile {
        WordPressComparisonProfile::NumericDottedV1 => "numeric-dotted/v1",
        WordPressComparisonProfile::PhpReleaseSubsetV1 => "php-release-subset/v1",
    }
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
const fn wordpress_version_resolution(resolution: WordPressVersionResolution) -> &'static str {
    match resolution {
        WordPressVersionResolution::Missing => "missing",
        WordPressVersionResolution::SupportedEquivalent => "supported_equivalent",
        WordPressVersionResolution::Conflicting => "conflicting",
        WordPressVersionResolution::Unsupported => "unsupported",
    }
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
const fn wordpress_version_resolution_reason(
    reason: WordPressVersionResolutionReason,
) -> &'static str {
    match reason {
        WordPressVersionResolutionReason::NoVersionEvidence => "no_version_evidence",
        WordPressVersionResolutionReason::SingleSupportedVersion => "single_supported_version",
        WordPressVersionResolutionReason::EquivalentSupportedVersions => {
            "equivalent_supported_versions"
        },
        WordPressVersionResolutionReason::ConflictingVersionEvidence => {
            "conflicting_version_evidence"
        },
        WordPressVersionResolutionReason::UnsupportedVersionEvidence => {
            "unsupported_version_evidence"
        },
    }
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
const fn wordpress_prerequisite_outcome(outcome: WordPressPrerequisiteOutcome) -> &'static str {
    match outcome {
        WordPressPrerequisiteOutcome::MatchedOnSuppliedFacts => "matched_on_supplied_facts",
        WordPressPrerequisiteOutcome::ContradictedOnSuppliedFacts => {
            "contradicted_on_supplied_facts"
        },
        WordPressPrerequisiteOutcome::Unknown => "unknown",
        WordPressPrerequisiteOutcome::Unsupported => "unsupported",
    }
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
const fn wordpress_applicability(applicability: WordPressApplicability) -> &'static str {
    match applicability {
        WordPressApplicability::CandidateMatchOnDeclaredFacts => {
            "candidate_match_on_declared_facts"
        },
        WordPressApplicability::ContradictedByDeclaredFacts => "contradicted_by_declared_facts",
        WordPressApplicability::IndeterminateMissingEvidence => "indeterminate_missing_evidence",
        WordPressApplicability::IndeterminateUnsupported => "indeterminate_unsupported",
    }
}

#[cfg(all(feature = "scanning", feature = "wordpress-review"))]
const fn wordpress_execution(status: WordPressExecutionStatus) -> &'static str {
    match status {
        WordPressExecutionStatus::NotPerformed => "not_performed",
    }
}

#[cfg(feature = "scanning")]
#[derive(Serialize)]
struct AssessmentItemDocument<'a> {
    schema: &'a str,
    capability_id: &'a str,
    subject_reference: String,
    title: &'a str,
    disposition: &'static str,
    claim_basis: &'static str,
    severity: Option<&'static str>,
    confidence_ppm: u32,
    fingerprint: &'a str,
    evidence_count: u64,
    redacted_summary: &'a str,
    category: &'a str,
    cwe: Option<&'a str>,
    remediation: AssessmentRemediationDocument<'a>,
    evidence_references: Vec<String>,
    control_evidence_references: Vec<String>,
    candidate_evidence_references: Vec<String>,
    case_reference: Option<String>,
    outcome_reference: Option<String>,
    verification_stage: Option<&'static str>,
}

#[cfg(feature = "scanning")]
impl<'a> AssessmentItemDocument<'a> {
    fn from_item(item: &'a crate::web_runtime::AssessmentItem) -> Result<Self, ReportError> {
        let remediation = item.remediation();
        let linkage = AssessmentBasisLinkageDocument::from_basis(item.basis())?;
        let evidence_count =
            u64::try_from(item.evidence_count()).map_err(|_| ReportError::Serialization)?;
        if linkage.reference_count()? != evidence_count {
            return Err(ReportError::Serialization);
        }
        Ok(Self {
            schema: item.schema(),
            capability_id: item.capability_id(),
            subject_reference: item.subject_reference().to_string(),
            title: item.title(),
            disposition: item.disposition().as_str(),
            claim_basis: assessment_basis_token(item.basis()),
            severity: item.severity().map(severity_token),
            confidence_ppm: item.confidence().parts_per_million(),
            fingerprint: item.fingerprint(),
            evidence_count,
            redacted_summary: item.redacted_summary(),
            category: item.category(),
            cwe: item.cwe(),
            remediation: AssessmentRemediationDocument {
                id: remediation.id(),
                summary: remediation.summary(),
            },
            evidence_references: linkage.evidence_references,
            control_evidence_references: linkage.control_evidence_references,
            candidate_evidence_references: linkage.candidate_evidence_references,
            case_reference: linkage.case_reference,
            outcome_reference: linkage.outcome_reference,
            verification_stage: linkage.verification_stage,
        })
    }

    fn required_metadata(&self) -> [(&'static str, String); 18] {
        [
            ("Item schema", self.schema.to_owned()),
            ("Capability", self.capability_id.to_owned()),
            ("Subject", self.subject_reference.clone()),
            ("Title", self.title.to_owned()),
            ("Claim basis", self.claim_basis.to_owned()),
            ("Confidence (ppm)", self.confidence_ppm.to_string()),
            ("Fingerprint", self.fingerprint.to_owned()),
            ("Evidence count", self.evidence_count.to_string()),
            ("Redacted summary", self.redacted_summary.to_owned()),
            ("Category", self.category.to_owned()),
            ("Remediation ID", self.remediation.id.to_owned()),
            ("Remediation summary", self.remediation.summary.to_owned()),
            (
                "Evidence references",
                assessment_reference_list(&self.evidence_references),
            ),
            (
                "Control evidence references",
                assessment_reference_list(&self.control_evidence_references),
            ),
            (
                "Candidate evidence references",
                assessment_reference_list(&self.candidate_evidence_references),
            ),
            (
                "Case reference",
                self.case_reference
                    .clone()
                    .unwrap_or_else(|| "not applicable".to_owned()),
            ),
            (
                "Outcome reference",
                self.outcome_reference
                    .clone()
                    .unwrap_or_else(|| "not applicable".to_owned()),
            ),
            (
                "Verification stage",
                self.verification_stage
                    .unwrap_or("not applicable")
                    .to_owned(),
            ),
        ]
    }

    fn validate(&self) -> Result<(), ReportError> {
        if !valid_opaque_assessment_reference(&self.subject_reference, "subject") {
            return Err(ReportError::Serialization);
        }
        let mut references: Vec<&str> = Vec::new();
        for reference in self
            .evidence_references
            .iter()
            .chain(&self.control_evidence_references)
            .chain(&self.candidate_evidence_references)
        {
            if !valid_opaque_assessment_reference(reference, "evidence")
                || references.contains(&reference.as_str())
            {
                return Err(ReportError::Serialization);
            }
            references.push(reference);
        }
        if u64::try_from(references.len()).map_err(|_| ReportError::Serialization)?
            != self.evidence_count
        {
            return Err(ReportError::Serialization);
        }
        let linkage_is_valid = match self.claim_basis {
            "observation" => {
                self.disposition == "informational"
                    && !self.evidence_references.is_empty()
                    && self.control_evidence_references.is_empty()
                    && self.candidate_evidence_references.is_empty()
                    && self.case_reference.is_none()
                    && self.outcome_reference.is_none()
                    && self.verification_stage.is_none()
            },
            "differential" => {
                let atomic_pair = self.evidence_references.len() == 1
                    && self.control_evidence_references.is_empty()
                    && self.candidate_evidence_references.is_empty();
                let matched_pair = self.evidence_references.is_empty()
                    && !self.control_evidence_references.is_empty()
                    && !self.candidate_evidence_references.is_empty();
                self.disposition == "needs_review"
                    && (atomic_pair || matched_pair)
                    && self.case_reference.is_none()
                    && self.outcome_reference.is_none()
                    && self.verification_stage.is_none()
            },
            "verifier_transition" => {
                self.disposition == "confirmed"
                    && !self.evidence_references.is_empty()
                    && self.control_evidence_references.is_empty()
                    && self.candidate_evidence_references.is_empty()
                    && self.case_reference.as_deref().is_some_and(|reference| {
                        valid_opaque_assessment_reference(reference, "case")
                    })
                    && self.outcome_reference.as_deref().is_some_and(|reference| {
                        valid_opaque_assessment_reference(reference, "outcome")
                    })
                    && matches!(self.verification_stage, Some("passive" | "active"))
            },
            _ => false,
        };
        if linkage_is_valid {
            Ok(())
        } else {
            Err(ReportError::Serialization)
        }
    }
}

#[cfg(feature = "scanning")]
fn valid_opaque_assessment_reference(value: &str, kind: &str) -> bool {
    let Some(suffix) = value
        .strip_prefix(kind)
        .and_then(|value| value.strip_prefix('-'))
    else {
        return false;
    };
    suffix.len() >= 4
        && suffix.bytes().all(|byte| byte.is_ascii_digit())
        && (suffix.len() == 4 || !suffix.starts_with('0'))
}

#[cfg(feature = "scanning")]
fn assessment_reference_list(references: &[String]) -> String {
    if references.is_empty() {
        "not applicable".to_owned()
    } else {
        references.join(", ")
    }
}

#[cfg(feature = "scanning")]
struct AssessmentBasisLinkageDocument {
    evidence_references: Vec<String>,
    control_evidence_references: Vec<String>,
    candidate_evidence_references: Vec<String>,
    case_reference: Option<String>,
    outcome_reference: Option<String>,
    verification_stage: Option<&'static str>,
}

#[cfg(feature = "scanning")]
impl AssessmentBasisLinkageDocument {
    fn from_basis(basis: &AssessmentBasis) -> Result<Self, ReportError> {
        match basis {
            AssessmentBasis::Observation(observation) => {
                let evidence_references = observation
                    .evidence()
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>();
                if evidence_references.is_empty() {
                    return Err(ReportError::Serialization);
                }
                Ok(Self {
                    evidence_references,
                    control_evidence_references: Vec::new(),
                    candidate_evidence_references: Vec::new(),
                    case_reference: None,
                    outcome_reference: None,
                    verification_stage: None,
                })
            },
            AssessmentBasis::Differential(differential) => {
                if let Some(reference) = differential.paired_comparison() {
                    if !differential.control().is_empty() || !differential.candidate().is_empty() {
                        return Err(ReportError::Serialization);
                    }
                    return Ok(Self {
                        evidence_references: vec![reference.to_string()],
                        control_evidence_references: Vec::new(),
                        candidate_evidence_references: Vec::new(),
                        case_reference: None,
                        outcome_reference: None,
                        verification_stage: None,
                    });
                }
                let control_evidence_references = differential
                    .control()
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>();
                let candidate_evidence_references = differential
                    .candidate()
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>();
                if control_evidence_references.is_empty()
                    || candidate_evidence_references.is_empty()
                {
                    return Err(ReportError::Serialization);
                }
                Ok(Self {
                    evidence_references: Vec::new(),
                    control_evidence_references,
                    candidate_evidence_references,
                    case_reference: None,
                    outcome_reference: None,
                    verification_stage: None,
                })
            },
            AssessmentBasis::Verifier(verifier) => {
                let evidence_references = verifier
                    .evidence()
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>();
                if evidence_references.is_empty() {
                    return Err(ReportError::Serialization);
                }
                Ok(Self {
                    evidence_references,
                    control_evidence_references: Vec::new(),
                    candidate_evidence_references: Vec::new(),
                    case_reference: Some(verifier.case_reference().to_string()),
                    outcome_reference: Some(verifier.outcome_reference().to_string()),
                    verification_stage: Some(verifier.stage().as_str()),
                })
            },
        }
    }

    fn reference_count(&self) -> Result<u64, ReportError> {
        self.evidence_references
            .len()
            .checked_add(self.control_evidence_references.len())
            .and_then(|count| count.checked_add(self.candidate_evidence_references.len()))
            .and_then(|count| u64::try_from(count).ok())
            .ok_or(ReportError::Serialization)
    }
}

#[cfg(feature = "scanning")]
#[derive(Serialize)]
struct AssessmentRemediationDocument<'a> {
    id: &'a str,
    summary: &'a str,
}

#[cfg(feature = "scanning")]
const fn assessment_basis_token(basis: &AssessmentBasis) -> &'static str {
    match basis {
        AssessmentBasis::Observation(_) => "observation",
        AssessmentBasis::Differential(_) => "differential",
        AssessmentBasis::Verifier(_) => "verifier_transition",
    }
}

#[derive(Serialize)]
struct ReportDocument<'a> {
    schema: &'static str,
    source_schema: &'a str,
    status: &'static str,
    stop_code: &'static str,
    target: &'a str,
    authorized_origin: &'a str,
    started_at: String,
    completed_at: String,
    accounting: AccountingDocument,
    steps: Vec<StepDocument<'a>>,
    outcomes: Vec<OutcomeDocument<'a>>,
}

impl<'a> ReportDocument<'a> {
    fn from_report(report: &'a RunReport) -> Result<Self, ReportError> {
        Ok(Self {
            schema: REPORT_DOCUMENT_SCHEMA,
            source_schema: report.schema(),
            status: run_status_token(report.status()),
            stop_code: stop_code_token(report.stop_reason().code()),
            target: report.target(),
            authorized_origin: report.authorized_origin(),
            started_at: report.started_at().to_rfc3339(),
            completed_at: report.completed_at().to_rfc3339(),
            accounting: AccountingDocument::from_report(report),
            steps: report.steps().iter().map(StepDocument::from_step).collect(),
            outcomes: report
                .outcomes()
                .iter()
                .map(OutcomeDocument::from_outcome)
                .collect::<Result<Vec<_>, _>>()?,
        })
    }

    fn metadata(&self) -> [(&'static str, &str); 8] {
        [
            ("Schema", self.schema),
            ("Source schema", self.source_schema),
            ("Status", self.status),
            ("Stop code", self.stop_code),
            ("Target", self.target),
            ("Authorized origin", self.authorized_origin),
            ("Started at", &self.started_at),
            ("Completed at", &self.completed_at),
        ]
    }
}

#[derive(Serialize)]
struct AccountingDocument {
    requests: AccountingDimension,
    response_body_bytes: AccountingDimension,
    request_body_bytes: AccountingDimension,
    wall_time_ms: AccountingDimension,
}

impl AccountingDocument {
    fn from_report(report: &RunReport) -> Self {
        let accounting = report.accounting();
        Self {
            requests: AccountingDimension::from_accounting(accounting.requests()),
            response_body_bytes: AccountingDimension::from_accounting(
                accounting.response_body_bytes(),
            ),
            request_body_bytes: AccountingDimension::from_accounting(
                accounting.request_body_bytes(),
            ),
            wall_time_ms: AccountingDimension::from_accounting(accounting.wall_time_ms()),
        }
    }

    fn dimensions(&self) -> [(&'static str, &AccountingDimension); 4] {
        [
            ("requests", &self.requests),
            ("response_body_bytes", &self.response_body_bytes),
            ("request_body_bytes", &self.request_body_bytes),
            ("wall_time_ms", &self.wall_time_ms),
        ]
    }
}

#[derive(Serialize)]
struct AccountingDimension {
    mode: &'static str,
    limit: Option<String>,
    consumed: Option<String>,
    remaining: Option<String>,
}

impl AccountingDimension {
    fn from_accounting(accounting: &ResourceAccounting) -> Self {
        Self {
            mode: accounting_mode_token(accounting.mode()),
            limit: accounting.limit().map(|value| value.to_string()),
            consumed: accounting.consumed().map(|value| value.to_string()),
            remaining: accounting.remaining().map(|value| value.to_string()),
        }
    }
}

#[derive(Serialize)]
struct StepDocument<'a> {
    ordinal: u32,
    action_id: &'a str,
    status: &'static str,
    duration_ms: String,
}

impl<'a> StepDocument<'a> {
    fn from_step(step: &'a termivar_core::RunStepReport) -> Self {
        Self {
            ordinal: step.ordinal(),
            action_id: step.action_id(),
            status: step_status_token(step.status()),
            duration_ms: step.duration_ms().to_string(),
        }
    }
}

#[derive(Serialize)]
struct OutcomeDocument<'a> {
    kind: &'static str,
    action_id: &'a str,
    severity: &'static str,
    disposition: &'static str,
    confidence_ppm: u32,
    evidence_count: u64,
    redacted_summary: &'a str,
}

impl<'a> OutcomeDocument<'a> {
    fn from_outcome(outcome: &'a RunOutcomeRecord) -> Result<Self, ReportError> {
        Ok(Self {
            kind: if outcome.verification_outcome().is_some() {
                "verification_outcome"
            } else {
                "unresolved_observation"
            },
            action_id: outcome.action_id(),
            severity: severity_token(outcome.severity()),
            disposition: disposition_token(outcome.disposition()),
            confidence_ppm: outcome.confidence().parts_per_million(),
            evidence_count: u64::try_from(outcome.evidence_ids().len())
                .map_err(|_| ReportError::Serialization)?,
            redacted_summary: outcome.redacted_summary(),
        })
    }
}

fn run_status_token(status: RunStatus) -> &'static str {
    match status {
        RunStatus::Complete => "complete",
        RunStatus::Partial => "partial",
        RunStatus::Cancelled => "cancelled",
        RunStatus::Failed => "failed",
        _ => "unrecognized",
    }
}

fn stop_code_token(code: RunStopCode) -> &'static str {
    match code {
        RunStopCode::Completed => "completed",
        RunStopCode::NoEligibleAction => "no_eligible_action",
        RunStopCode::BudgetExhausted => "budget_exhausted",
        RunStopCode::ReportLimitExceeded => "report_limit_exceeded",
        RunStopCode::Cancelled => "cancelled",
        RunStopCode::StepFailed => "step_failed",
        RunStopCode::StepTimedOut => "step_timed_out",
        RunStopCode::TaskJoinFailed => "task_join_failed",
        RunStopCode::RuntimeFailed => "runtime_failed",
        _ => "unrecognized",
    }
}

fn step_status_token(status: RunStepStatus) -> &'static str {
    match status {
        RunStepStatus::Succeeded => "succeeded",
        RunStepStatus::Failed => "failed",
        RunStepStatus::TimedOut => "timed_out",
        RunStepStatus::Cancelled => "cancelled",
        RunStepStatus::Skipped => "skipped",
        RunStepStatus::BudgetExhausted => "budget_exhausted",
        _ => "unrecognized",
    }
}

fn accounting_mode_token(mode: ResourceAccountingMode) -> &'static str {
    match mode {
        ResourceAccountingMode::Metered => "metered",
        ResourceAccountingMode::Observed => "observed",
        ResourceAccountingMode::Unmetered => "unmetered",
        _ => "unrecognized",
    }
}

fn disposition_token(disposition: OutcomeStatus) -> &'static str {
    match disposition {
        OutcomeStatus::Success => "success",
        OutcomeStatus::Blocked => "blocked",
        OutcomeStatus::Unknown => "unknown",
        OutcomeStatus::FalsePositive => "false_positive",
        OutcomeStatus::NeedsReview => "needs_review",
        OutcomeStatus::ConfirmedNegative => "confirmed_negative",
        _ => "unrecognized",
    }
}

fn severity_token(severity: SecuritySeverity) -> &'static str {
    match severity {
        SecuritySeverity::Info => "info",
        SecuritySeverity::Low => "low",
        SecuritySeverity::Medium => "medium",
        SecuritySeverity::High => "high",
        SecuritySeverity::Critical => "critical",
        _ => "unrecognized",
    }
}

fn write_visible_codepoint(output: &mut RenderBuffer, character: char) -> Result<(), ReportError> {
    output.push_fmt(format_args!("\\u{{{:04X}}}", u32::from(character)))
}

fn is_bidi_control(character: char) -> bool {
    matches!(
        character,
        '\u{061C}'
            | '\u{200E}'
            | '\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2066}'..='\u{2069}'
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use termivar_core::{
        EntityId, EvidenceId, Outcome, Probability, RunAccounting, RunReportInput, RunStepReport,
        RunStopReason, VerificationStage,
    };

    const PRIVATE_SUBJECT: &str = "private-subject-sentinel";
    const PRIVATE_EVIDENCE: &str = "private-evidence-sentinel";
    const PRIVATE_RATIONALE: &str = "private-rationale-sentinel";
    const PRIVATE_CASE: &str = "private-case-sentinel";
    const PRIVATE_RULE: &str = "private-rule-sentinel";
    const PRIVATE_HYPOTHESIS: &str = "private-hypothesis-sentinel";
    const PRIVATE_STEP_DETAIL: &str = "private-step-detail-sentinel";

    fn complete_report(target: &str, summary: &str) -> RunReport {
        report_for_status(
            RunStatus::Complete,
            RunStopCode::Completed,
            vec![RunStepReport::new(
                1,
                "scan.observe",
                RunStepStatus::Succeeded,
                25,
                Some(PRIVATE_STEP_DETAIL.to_string()),
            )
            .unwrap()],
            target,
            summary,
        )
    }

    fn report_for_status(
        status: RunStatus,
        stop_code: RunStopCode,
        steps: Vec<RunStepReport>,
        target: &str,
        summary: &str,
    ) -> RunReport {
        let outcome = Outcome::verified(
            PRIVATE_CASE,
            EntityId::new(PRIVATE_SUBJECT).unwrap(),
            "scan.observe",
            PRIVATE_HYPOTHESIS,
            PRIVATE_RULE,
            VerificationStage::Passive,
            OutcomeStatus::Success,
            Probability::from_parts_per_million(812_345).unwrap(),
            PRIVATE_RATIONALE,
            BTreeSet::from([EvidenceId::parse(PRIVATE_EVIDENCE).unwrap()]),
        )
        .unwrap();
        let outcome = RunOutcomeRecord::from_outcome(outcome, summary).unwrap();
        let input = RunReportInput::new(
            status,
            RunStopReason::new(stop_code, "private-stop-detail-sentinel").unwrap(),
            target,
            "https://example.test",
            "2026-08-20T10:00:00Z".parse().unwrap(),
            "2026-08-20T10:00:01Z".parse().unwrap(),
        )
        .unwrap()
        .with_accounting(RunAccounting::new(
            ResourceAccounting::metered(10, 4),
            ResourceAccounting::observed(900),
            ResourceAccounting::unmetered(),
            ResourceAccounting::metered(2_000, 1_000),
        ))
        .with_steps(steps)
        .with_outcomes(if status == RunStatus::Failed {
            Vec::new()
        } else {
            vec![outcome]
        });
        RunReport::new(input).unwrap()
    }

    fn maximum_accounting_report() -> RunReport {
        let outcome = RunOutcomeRecord::unresolved(
            EntityId::new(PRIVATE_SUBJECT).unwrap(),
            "scan.observe",
            PRIVATE_RATIONALE,
            "summary",
        )
        .unwrap();
        let input = RunReportInput::new(
            RunStatus::Complete,
            RunStopReason::new(RunStopCode::Completed, "done").unwrap(),
            "target",
            "origin",
            "2026-08-20T10:00:00Z".parse().unwrap(),
            "2026-08-20T10:00:01Z".parse().unwrap(),
        )
        .unwrap()
        .with_accounting(RunAccounting::new(
            ResourceAccounting::metered(u64::MAX, u64::MAX),
            ResourceAccounting::observed(u64::MAX),
            ResourceAccounting::metered(u64::MAX, 0),
            ResourceAccounting::metered(u64::MAX, 1),
        ))
        .with_steps(vec![RunStepReport::new(
            1,
            "scan.observe",
            RunStepStatus::Succeeded,
            u64::MAX,
            None,
        )
        .unwrap()])
        .with_outcomes(vec![outcome]);
        RunReport::new(input).unwrap()
    }

    fn parse_csv_line(line: &str) -> Vec<String> {
        let bytes = line.as_bytes();
        let mut index = 0;
        let mut cells = Vec::new();
        while index < bytes.len() {
            assert_eq!(bytes[index], b'"');
            index += 1;
            let mut cell = Vec::new();
            loop {
                assert!(index < bytes.len());
                if bytes[index] == b'"' {
                    if bytes.get(index + 1) == Some(&b'"') {
                        cell.push(b'"');
                        index += 2;
                        continue;
                    }
                    index += 1;
                    break;
                }
                cell.push(bytes[index]);
                index += 1;
            }
            cells.push(String::from_utf8(cell).unwrap());
            if index == bytes.len() {
                break;
            }
            assert_eq!(bytes[index], b',');
            index += 1;
        }
        cells
    }

    #[cfg(feature = "scanning")]
    fn observation_assessment_document(text: &str) -> AssessmentDocument<'_> {
        AssessmentDocument {
            schema: ASSESSMENT_REPORT_DOCUMENT_SCHEMA,
            source_schema: crate::web_runtime::ASSESSMENT_RUN_REPORT_SCHEMA,
            run_schema: termivar_core::RUN_REPORT_SCHEMA,
            profile_schema: crate::web_runtime::SCAN_PROFILE_V1_SCHEMA,
            profile: "web-review",
            status: "complete",
            subject_count: 1,
            item_count: 1,
            #[cfg(feature = "authorization-review")]
            authorization_review: None,
            #[cfg(feature = "openapi-review")]
            openapi_review: None,
            #[cfg(feature = "rest-review")]
            rest_review: None,
            #[cfg(feature = "wordpress-review")]
            wordpress_review: None,
            #[cfg(feature = "wordpress-review")]
            wordpress_discovery: None,
            items: vec![AssessmentItemDocument {
                schema: crate::web_runtime::ASSESSMENT_ITEM_SCHEMA,
                capability_id: text,
                subject_reference: "subject-0000".to_owned(),
                title: text,
                disposition: "informational",
                claim_basis: "observation",
                severity: None,
                confidence_ppm: 750_000,
                fingerprint: text,
                evidence_count: 1,
                redacted_summary: text,
                category: text,
                cwe: None,
                remediation: AssessmentRemediationDocument {
                    id: text,
                    summary: text,
                },
                evidence_references: vec!["evidence-0000".to_owned()],
                control_evidence_references: Vec::new(),
                candidate_evidence_references: Vec::new(),
                case_reference: None,
                outcome_reference: None,
                verification_stage: None,
            }],
        }
    }

    #[cfg(feature = "scanning")]
    fn complete_assessment_document() -> AssessmentDocument<'static> {
        let mut document = observation_assessment_document("passive.header.hsts.missing@1");
        document.items[0].title = "Strict transport policy was not observed";
        document.items[0].fingerprint = "assessment-fingerprint-v1:0001";
        document.items[0].redacted_summary = "Bounded response metadata did not include HSTS.";
        document.items[0].category = "transport-policy";
        document.items[0].remediation = AssessmentRemediationDocument {
            id: "remediation.transport.hsts@1",
            summary: "Review whether this HTTPS response should declare HSTS.",
        };
        document.items.push(AssessmentItemDocument {
            schema: crate::web_runtime::ASSESSMENT_ITEM_SCHEMA,
            capability_id: "cors.policy.relationship@1",
            subject_reference: "subject-0000".to_owned(),
            title: "CORS policy relationship warrants review",
            disposition: "needs_review",
            claim_basis: "differential",
            severity: Some("low"),
            confidence_ppm: 825_000,
            fingerprint: "assessment-fingerprint-v1:0002",
            evidence_count: 2,
            redacted_summary: "A matched control and candidate differed under review policy.",
            category: "cross-origin-policy",
            cwe: Some("CWE-942"),
            remediation: AssessmentRemediationDocument {
                id: "remediation.cors.policy@1",
                summary: "Review the intended origin and credential relationship.",
            },
            evidence_references: Vec::new(),
            control_evidence_references: vec!["evidence-0001".to_owned()],
            candidate_evidence_references: vec!["evidence-0002".to_owned()],
            case_reference: None,
            outcome_reference: None,
            verification_stage: None,
        });
        document.items.push(AssessmentItemDocument {
            schema: crate::web_runtime::ASSESSMENT_ITEM_SCHEMA,
            capability_id: "review.confirmed.test-boundary@1",
            subject_reference: "subject-0000".to_owned(),
            title: "Verifier-authorized transition",
            disposition: "confirmed",
            claim_basis: "verifier_transition",
            severity: Some("high"),
            confidence_ppm: 990_000,
            fingerprint: "assessment-fingerprint-v1:0003",
            evidence_count: 2,
            redacted_summary: "A case-correlated verifier transition satisfied claim policy.",
            category: "verification-boundary",
            cwe: Some("CWE-20"),
            remediation: AssessmentRemediationDocument {
                id: "remediation.verified.test-boundary@1",
                summary: "Apply the capability-owned remediation and verify the correction.",
            },
            evidence_references: vec!["evidence-0003".to_owned(), "evidence-0004".to_owned()],
            control_evidence_references: Vec::new(),
            candidate_evidence_references: Vec::new(),
            case_reference: Some("case-0000".to_owned()),
            outcome_reference: Some("outcome-0000".to_owned()),
            verification_stage: Some("active"),
        });
        document.item_count = 3;
        document
    }

    #[cfg(all(feature = "scanning", feature = "openapi-review"))]
    fn observed_openapi_assessment_document() -> AssessmentDocument<'static> {
        let mut document = observation_assessment_document(OPENAPI_REVIEW_CAPABILITY_ID);
        document.items[0].title = "OpenAPI contract observed";
        document.items[0].fingerprint = "assessment-openapi-fingerprint-v1:0001";
        document.items[0].redacted_summary =
            "A bounded OpenAPI contract was reproduced by one anonymous GET replay.";
        document.items[0].category = "api-surface";
        document.items[0].remediation = AssessmentRemediationDocument {
            id: "api.openapi-contract-review@1",
            summary: "Confirm that publishing this OpenAPI contract matches deployment policy.",
        };
        document.openapi_review = Some(AssessmentOpenApiAuditDocument {
            schema: "security.openapi-review-audit/v1",
            capability_id: OPENAPI_REVIEW_CAPABILITY_ID,
            outcome: openapi_outcome(OpenApiRuntimeOutcome::DocumentObserved),
            candidate_source: crate::web_runtime::OpenApiCandidateSource::DiscoveredOpenApiJson,
            request_count: 2,
            active_verification_count: 1,
            version: Some("3.1.0"),
            semantic_digest: Some(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
            ),
            path_count: 3,
            operation_count: 5,
            get_operation_count: 2,
            write_operation_count: 3,
            path_parameter_count: 1,
            query_parameter_count: 2,
            explicit_auth_operation_count: 3,
            anonymous_operation_count: 2,
            url_like_operation_count: 1,
            multipart_operation_count: 1,
            deprecated_operation_count: 1,
            replay_matched: true,
            item_projected: true,
        });
        document
    }

    #[cfg(all(feature = "scanning", feature = "rest-review"))]
    fn observed_rest_assessment_document() -> AssessmentDocument<'static> {
        let mut document = observation_assessment_document(REST_REVIEW_CAPABILITY_ID);
        document.items[0].title = "REST operation surface observed";
        document.items[0].fingerprint = "assessment-rest-fingerprint-v1:0001";
        document.items[0].redacted_summary =
            "Two anonymous exact-origin GET requests reproduced the same bounded JSON resource structure.";
        document.items[0].category = "api-surface";
        document.items[0].remediation = AssessmentRemediationDocument {
            id: "api.rest-readonly-surface-review@1",
            summary: "Confirm that anonymously exposing this documented read-only operation matches deployment policy.",
        };
        document.rest_review = Some(AssessmentRestAuditDocument {
            schema: "security.rest-readonly-review-audit/v1",
            capability_id: REST_REVIEW_CAPABILITY_ID,
            enabled: true,
            method: "get",
            outcome: rest_outcome(RestRuntimeOutcome::SurfaceObserved),
            request_count: 2,
            active_verification_count: 1,
            eligible_operation_count: 3,
            selected_operation_identity: Some(
                "openapi-operation-sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .to_owned(),
            ),
            documented_response: Some(rest_documented_response(
                RestDocumentedResponseClass::JsonCompatible,
            )),
            observed_media: rest_observed_media(RestObservedMediaClass::JsonCompatible),
            status_class: Some(2),
            replay_stable: true,
            item_projected: true,
        });
        document
    }

    #[cfg(all(feature = "scanning", feature = "wordpress-review"))]
    fn observed_wordpress_assessment_document() -> AssessmentDocument<'static> {
        let mut document = observation_assessment_document(WORDPRESS_REVIEW_CAPABILITY_ID);
        document.items[0].title = "WordPress surface hints observed";
        document.items[0].fingerprint = "assessment-wordpress-fingerprint-v1:0001";
        document.items[0].redacted_summary =
            "The root response contained bounded structured WordPress hints; installation authenticity and advisory impact were not established.";
        document.items[0].category = "technology-observation";
        document.items[0].remediation = AssessmentRemediationDocument {
            id: "wordpress-inventory-review",
            summary: "Review supplied WordPress context and advisory applicability independently.",
        };
        document.wordpress_review = Some(AssessmentWordPressAuditDocument {
            schema: "security.wordpress-review-audit/v1",
            review_basis_schema: None,
            capability_id: WORDPRESS_REVIEW_CAPABILITY_ID,
            catalog_status: "evaluated",
            catalog_schema: None,
            catalog: Some(WordPressCatalogDocument {
                id: "termivar-synthetic-wordpress-reporting".to_owned(),
                revision: "synthetic-v1".to_owned(),
                retrieved_on: "2026-09-06".to_owned(),
            }),
            inventory_import: None,
            external_review: None,
            signal_count: 1,
            evidence_reference_count: 1,
            additional_request_count: 0,
            item_projected: true,
            component_count: 1,
            advisory_count: 1,
            components: vec![WordPressComponentDocument {
                identity: WordPressComponentIdentityDocument {
                    kind: "core",
                    slug: "wordpress".to_owned(),
                },
                evidence_class: "observed_hint",
                identity_sources: vec!["generator_metadata"],
                confidence_classes: vec!["public_declaration"],
                versions: vec![WordPressVersionEvidenceDocument {
                    value: "6.9.4".to_owned(),
                    source: "generator_metadata",
                    confidence: "public_declaration",
                }],
                activation: None,
                inventory_status: None,
            }],
            advisories: vec![WordPressAdvisoryDocument {
                id: "SYNTHETIC-REPORTING-WORDPRESS-0001".to_owned(),
                component: WordPressComponentIdentityDocument {
                    kind: "core",
                    slug: "wordpress".to_owned(),
                },
                source: WordPressAdvisorySourceDocument {
                    reference: "https://example.invalid/termivar/synthetic/reporting".to_owned(),
                    revision: "synthetic-v1".to_owned(),
                    retrieved_on: "2026-09-06".to_owned(),
                    usage_basis:
                        "Fictional test data created for Termivar reporting; not a real advisory."
                            .to_owned(),
                },
                cve: None,
                summary: "Synthetic bounded summary <script>inert()</script>".to_owned(),
                affected_ranges: vec![WordPressAffectedRangeDocument {
                    lower: Some(WordPressVersionEndpointDocument {
                        declared: "6.9.0".to_owned(),
                        inclusive: true,
                    }),
                    upper: Some(WordPressVersionEndpointDocument {
                        declared: "6.9.5".to_owned(),
                        inclusive: false,
                    }),
                }],
                fixed_versions: vec!["6.9.5".to_owned()],
                prerequisites: vec![WordPressPrerequisiteDocument {
                    kind: "hosting_os",
                    expected: "linux".to_owned(),
                    patch_id: None,
                    outcome: "unknown",
                }],
                remediation: Some("Review the supplied upstream remediation guidance.".to_owned()),
                comparison_profile: None,
                version_resolution: None,
                version_resolution_reason: None,
                component_evidence: "observed_hint",
                version_relation: "within_declared_range",
                applicability: "indeterminate_missing_evidence",
                exploit_execution: "not_performed",
                impact_validation: "not_performed",
            }],
        });
        document
    }

    #[cfg(all(feature = "scanning", feature = "wordpress-review"))]
    fn discovered_wordpress_assessment_document() -> AssessmentDocument<'static> {
        let mut document = observed_wordpress_assessment_document();
        document.items[0].fingerprint =
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        document.items.push(AssessmentItemDocument {
            schema: crate::web_runtime::ASSESSMENT_ITEM_SCHEMA,
            capability_id: WORDPRESS_DISCOVERY_OBSERVATION_CAPABILITY_ID,
            subject_reference: "subject-0000".to_owned(),
            title: "WordPress metadata-source response outcome observed",
            disposition: "informational",
            claim_basis: "observation",
            severity: None,
            confidence_ppm: 550_000,
            fingerprint:
                "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            evidence_count: 3,
            redacted_summary: "Bounded response evidence from selected public WordPress metadata sources was collected; usable metadata, installation authenticity, vulnerable-code reachability, and advisory impact were not established.",
            category: "wordpress-metadata-source-response",
            cwe: None,
            remediation: AssessmentRemediationDocument {
                id: "wordpress-metadata-review",
                summary: "Confirm the installation inventory and source-qualified metadata before making a security or remediation decision.",
            },
            evidence_references: vec![
                "evidence-0001".to_owned(),
                "evidence-0002".to_owned(),
                "evidence-0003".to_owned(),
            ],
            control_evidence_references: Vec::new(),
            candidate_evidence_references: Vec::new(),
            case_reference: None,
            outcome_reference: None,
            verification_stage: None,
        });
        document.item_count = document.items.len() as u64;
        let review = document.wordpress_review.as_mut().unwrap();
        review.schema = "security.wordpress-review-audit/v7";
        review.review_basis_schema = Some("security.wordpress-review-audit/v1");
        review.additional_request_count = 3;
        review.components.push(WordPressComponentDocument {
            identity: WordPressComponentIdentityDocument {
                kind: "theme",
                slug: "termivar-child".to_owned(),
            },
            evidence_class: "observed_hint",
            identity_sources: vec!["same_origin_asset_path", "theme_stylesheet_declaration"],
            confidence_classes: vec!["structural_hint", "public_declaration"],
            versions: vec![WordPressVersionEvidenceDocument {
                value: "1.2.3".to_owned(),
                source: "theme_stylesheet_declaration",
                confidence: "public_declaration",
            }],
            activation: None,
            inventory_status: None,
        });
        review.components.push(WordPressComponentDocument {
            identity: WordPressComponentIdentityDocument {
                kind: "plugin",
                slug: "termivar-metadata-lab".to_owned(),
            },
            evidence_class: "observed_hint",
            identity_sources: vec!["same_origin_asset_path"],
            confidence_classes: vec!["structural_hint"],
            versions: Vec::new(),
            activation: None,
            inventory_status: None,
        });
        review.component_count = review.components.len();
        document.wordpress_discovery = Some(AssessmentWordPressDiscoveryAuditDocument {
            schema: WORDPRESS_DISCOVERY_AUDIT_SCHEMA,
            capability_id: WORDPRESS_DISCOVERY_CAPABILITY_ID,
            policy_id: WORDPRESS_DISCOVERY_POLICY_ID,
            selected: true,
            method: "get",
            credential_mode: "anonymous",
            seed_count: 3,
            candidate_count: 3,
            candidate_limit_reached: false,
            omitted_candidate_count: 0,
            attempted_request_count: 3,
            completed_response_count: 3,
            committed_response_count: 3,
            response_bytes: 768,
            source_count: 3,
            sources: vec![
                WordPressDiscoverySourceDocument {
                    kind: "rest_index",
                    component: None,
                    parent_depth: 0,
                    outcome: "observed",
                    request_attempted: true,
                    response_bytes: 256,
                    evidence_reference_count: 1,
                    evidence_references: vec!["evidence-0001".to_owned()],
                    namespaces: vec!["wp/v2".to_owned(), "termivar-lab/v1".to_owned()],
                    theme: None,
                    plugin: None,
                },
                WordPressDiscoverySourceDocument {
                    kind: "theme_stylesheet",
                    component: Some(WordPressComponentIdentityDocument {
                        kind: "theme",
                        slug: "termivar-child".to_owned(),
                    }),
                    parent_depth: 0,
                    outcome: "observed",
                    request_attempted: true,
                    response_bytes: 256,
                    evidence_reference_count: 1,
                    evidence_references: vec!["evidence-0002".to_owned()],
                    namespaces: Vec::new(),
                    theme: Some(WordPressThemeDiscoveryDocument {
                        name: Some("Termivar child".to_owned()),
                        version: Some("1.2.3".to_owned()),
                        template: Some("termivar-parent".to_owned()),
                        requires_wordpress: Some("6.8".to_owned()),
                        requires_php: Some("8.1".to_owned()),
                        tested_up_to: Some("6.9".to_owned()),
                    }),
                    plugin: None,
                },
                WordPressDiscoverySourceDocument {
                    kind: "plugin_readme",
                    component: Some(WordPressComponentIdentityDocument {
                        kind: "plugin",
                        slug: "termivar-metadata-lab".to_owned(),
                    }),
                    parent_depth: 0,
                    outcome: "observed",
                    request_attempted: true,
                    response_bytes: 256,
                    evidence_reference_count: 1,
                    evidence_references: vec!["evidence-0003".to_owned()],
                    namespaces: Vec::new(),
                    theme: None,
                    plugin: Some(WordPressPluginDiscoveryDocument {
                        name: Some("Termivar metadata lab".to_owned()),
                        stable_tag: Some("9.9.9".to_owned()),
                        requires_wordpress: Some("6.8".to_owned()),
                        requires_php: Some("8.1".to_owned()),
                        tested_up_to: Some("6.9".to_owned()),
                    }),
                },
            ],
        });
        document
    }

    #[cfg(all(feature = "scanning", feature = "wordpress-review"))]
    fn profiled_wordpress_assessment_document() -> AssessmentDocument<'static> {
        let mut document = observed_wordpress_assessment_document();
        let audit = document.wordpress_review.as_mut().unwrap();
        audit.schema = "security.wordpress-review-audit/v2";
        audit.catalog.as_mut().unwrap().revision = "synthetic-v2".to_owned();
        audit.components[0].versions[0].value = "2.4.0-beta1".to_owned();
        let advisory = &mut audit.advisories[0];
        advisory.affected_ranges = vec![WordPressAffectedRangeDocument {
            lower: Some(WordPressVersionEndpointDocument {
                declared: "2.4.0-beta0".to_owned(),
                inclusive: true,
            }),
            upper: Some(WordPressVersionEndpointDocument {
                declared: "2.4.0".to_owned(),
                inclusive: false,
            }),
        }];
        advisory.fixed_versions = vec!["2.4.0".to_owned()];
        advisory.comparison_profile = Some("php-release-subset/v1");
        advisory.version_resolution = Some("supported_equivalent");
        advisory.version_resolution_reason = Some("single_supported_version");
        advisory.version_relation = "within_declared_range";
        advisory.applicability = "candidate_match_on_declared_facts";
        document
    }

    #[cfg(all(feature = "scanning", feature = "wordpress-review"))]
    fn saved_inventory_wordpress_assessment_document() -> AssessmentDocument<'static> {
        let mut document = observed_wordpress_assessment_document();
        document.items[0].fingerprint =
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let audit = document.wordpress_review.as_mut().unwrap();
        audit.schema = "security.wordpress-review-audit/v3";
        audit.catalog_schema = Some(WORDPRESS_ADVISORY_CATALOG_SCHEMA);
        audit.inventory_import = Some(WordPressInventoryImportDocument {
            coverage: WordPressInventoryCoverageDocument {
                core: "not_supplied",
                plugins: "supplied",
                themes: "not_supplied",
            },
            component_count: 1,
            limitations: Vec::new(),
            inputs: vec![WordPressInventoryInputDocument {
                class: "wp_cli_plugins_json",
                byte_length: 71,
                sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .to_owned(),
            }],
        });
        audit.components.push(WordPressComponentDocument {
            identity: WordPressComponentIdentityDocument {
                kind: "plugin",
                slug: "synthetic-plugin".to_owned(),
            },
            evidence_class: "operator_supplied",
            identity_sources: vec!["operator_context"],
            confidence_classes: vec!["operator_assertion"],
            versions: vec![WordPressVersionEvidenceDocument {
                value: "1.2.3-vendor".to_owned(),
                source: "operator_context",
                confidence: "operator_assertion",
            }],
            activation: Some("active"),
            inventory_status: Some("active"),
        });
        audit.component_count = audit.components.len();
        document
    }

    #[cfg(all(feature = "scanning", feature = "wordpress-review"))]
    fn external_wordpress_assessment_document() -> AssessmentDocument<'static> {
        external_wordpress_assessment_document_from_bytes(include_bytes!(
            "../../../docs/examples/wordpress-review/wordfence-v3/production.synthetic.json"
        ))
    }

    #[cfg(all(feature = "scanning", feature = "wordpress-review"))]
    fn external_wordpress_assessment_document_from_bytes(
        bytes: &[u8],
    ) -> AssessmentDocument<'static> {
        let catalog = crate::wordpress_review::parse_wordfence_v3_production(bytes).unwrap();
        let inputs = crate::wordpress_review::WordPressReviewInputs::new(None, None)
            .with_wordfence_v3_catalog(catalog)
            .unwrap();
        let signals = [
            crate::wordpress_review::WordPressComponentSignal::same_origin_asset(
                WordPressComponentKind::Plugin,
                "termivar-fixture-component",
            )
            .unwrap(),
        ];
        let result = crate::wordpress_review::evaluate_wordpress_review(&signals, &inputs).unwrap();

        let mut document = observed_wordpress_assessment_document();
        document.items[0].fingerprint =
            "sha256:1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let audit = document.wordpress_review.as_mut().unwrap();
        audit.catalog = None;
        audit.catalog_schema = None;
        audit.inventory_import = None;
        audit.advisories.clear();
        audit.advisory_count = 0;
        audit.components[0] = WordPressComponentDocument {
            identity: WordPressComponentIdentityDocument {
                kind: "plugin",
                slug: "termivar-fixture-component".to_owned(),
            },
            evidence_class: "observed_hint",
            identity_sources: vec!["same_origin_asset_path"],
            confidence_classes: vec!["structural_hint"],
            versions: Vec::new(),
            activation: None,
            inventory_status: None,
        };
        let external_review = wordpress_external_review_document(result.external_review().unwrap());
        audit.schema = if external_review.resource_policy.is_some() {
            "security.wordpress-review-audit/v6"
        } else {
            "security.wordpress-review-audit/v4"
        };
        audit.external_review = Some(external_review);
        document
    }

    #[cfg(all(feature = "scanning", feature = "wordpress-review"))]
    fn external_fixture_source_association_fingerprint() -> String {
        let catalog = crate::wordpress_review::parse_wordfence_v3_production(
            &include_bytes!(
                "../../../docs/examples/wordpress-review/wordfence-v3/production.synthetic.json"
            )[..],
        )
        .unwrap();
        let inputs = crate::wordpress_review::WordPressReviewInputs::new(None, None)
            .with_wordfence_v3_catalog(catalog)
            .unwrap();
        let signals = [
            crate::wordpress_review::WordPressComponentSignal::same_origin_asset(
                WordPressComponentKind::Plugin,
                "termivar-fixture-component",
            )
            .unwrap(),
        ];
        let result = crate::wordpress_review::evaluate_wordpress_review(&signals, &inputs).unwrap();
        let evaluation = result
            .external_review()
            .unwrap()
            .evaluations()
            .first()
            .unwrap();
        format!(
            "wordfence-source-association-sha256:{}",
            lowercase_hex(evaluation.key().source_association_sha256())
        )
    }

    #[cfg(all(feature = "scanning", feature = "wordpress-review"))]
    fn explicitly_profiled_external_wordpress_assessment_document(
        profile: WordPressComparisonProfile,
    ) -> AssessmentDocument<'static> {
        let catalog = crate::wordpress_review::parse_wordfence_v3_production(
            &include_bytes!(
                "../../../docs/examples/wordpress-review/wordfence-v3/production.synthetic.json"
            )[..],
        )
        .unwrap();
        let context = crate::wordpress_review::parse_wordpress_context(
            br#"{
              "schema":"security.wordpress-context/v1",
              "root":"https://example.test/",
              "components":[
                {"kind":"plugin","slug":"termivar-fixture-component","version":"1.0"}
              ]
            }"#,
        )
        .unwrap();
        let inputs = crate::wordpress_review::WordPressReviewInputs::new(Some(context), None)
            .with_wordfence_v3_catalog(catalog)
            .unwrap()
            .with_external_version_profile(profile)
            .unwrap();
        let signals = [
            crate::wordpress_review::WordPressComponentSignal::same_origin_asset(
                WordPressComponentKind::Plugin,
                "termivar-fixture-component",
            )
            .unwrap(),
        ];
        let result = crate::wordpress_review::evaluate_wordpress_review(&signals, &inputs).unwrap();

        let mut document = observed_wordpress_assessment_document();
        document.items[0].fingerprint =
            "sha256:2123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let audit = document.wordpress_review.as_mut().unwrap();
        audit.catalog = None;
        audit.catalog_schema = None;
        audit.inventory_import = None;
        audit.advisories.clear();
        audit.advisory_count = 0;
        audit.components = result
            .components()
            .iter()
            .map(|component| WordPressComponentDocument {
                identity: wordpress_component_identity(component.identity()),
                evidence_class: wordpress_evidence_class(component.evidence_class()),
                identity_sources: component
                    .identity_sources()
                    .iter()
                    .copied()
                    .map(wordpress_evidence_source)
                    .collect(),
                confidence_classes: component
                    .confidence_classes()
                    .iter()
                    .copied()
                    .map(wordpress_confidence)
                    .collect(),
                versions: component
                    .versions()
                    .iter()
                    .map(|version| WordPressVersionEvidenceDocument {
                        value: version.value().to_owned(),
                        source: wordpress_evidence_source(version.source()),
                        confidence: wordpress_confidence(version.confidence()),
                    })
                    .collect(),
                activation: component.activation().map(wordpress_activation),
                inventory_status: component
                    .inventory_status()
                    .map(wordpress_inventory_entry_status),
            })
            .collect();
        audit.component_count = audit.components.len();
        let external_review = wordpress_external_review_document(result.external_review().unwrap());
        audit.schema = if external_review.resource_policy.is_some() {
            "security.wordpress-review-audit/v6"
        } else {
            "security.wordpress-review-audit/v5"
        };
        audit.external_review = Some(external_review);
        document
    }

    #[cfg(all(feature = "scanning", feature = "wordpress-review"))]
    fn source_identity_external_wordpress_assessment_document(
        profile: Option<WordPressComparisonProfile>,
        collision: bool,
    ) -> AssessmentDocument<'static> {
        const FIRST_ID: &str = "00000000-0000-4000-8000-000000000001";
        let mut source: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../../docs/examples/wordpress-review/wordfence-v3/production.synthetic.json"
        ))
        .unwrap();
        let software = source[FIRST_ID]["software"].as_array_mut().unwrap();
        if collision {
            let mut alternate = software[0].clone();
            alternate["slug"] = serde_json::Value::String("TERMIVAR-FIXTURE-COMPONENT".to_owned());
            software.push(alternate);
        } else {
            software[0]["slug"] =
                serde_json::Value::String("Termivar-Fixture-Component".to_owned());
        }
        let encoded = serde_json::to_vec(&source).unwrap();
        let catalog =
            crate::wordpress_review::parse_wordfence_v3_production(encoded.as_slice()).unwrap();
        let context = profile.map(|_| {
            crate::wordpress_review::parse_wordpress_context(
                br#"{
                  "schema":"security.wordpress-context/v1",
                  "root":"https://example.test/",
                  "components":[
                    {"kind":"plugin","slug":"termivar-fixture-component","version":"1.0"}
                  ]
                }"#,
            )
            .unwrap()
        });
        let inputs = crate::wordpress_review::WordPressReviewInputs::new(context, None)
            .with_wordfence_v3_catalog(catalog)
            .unwrap();
        let inputs = if let Some(profile) = profile {
            inputs.with_external_version_profile(profile).unwrap()
        } else {
            inputs
        };
        let signals = [
            crate::wordpress_review::WordPressComponentSignal::same_origin_asset(
                WordPressComponentKind::Plugin,
                "termivar-fixture-component",
            )
            .unwrap(),
        ];
        let result = crate::wordpress_review::evaluate_wordpress_review(&signals, &inputs).unwrap();

        let mut document = profile.map_or_else(external_wordpress_assessment_document, |profile| {
            explicitly_profiled_external_wordpress_assessment_document(profile)
        });
        let audit = document.wordpress_review.as_mut().unwrap();
        audit.schema = "security.wordpress-review-audit/v6";
        audit.external_review = Some(wordpress_external_review_document(
            result.external_review().unwrap(),
        ));
        document
    }

    #[cfg(all(feature = "scanning", feature = "wordpress-review"))]
    fn unresolved_identity_external_wordpress_assessment_document(
        profile: Option<WordPressComparisonProfile>,
    ) -> AssessmentDocument<'static> {
        unresolved_identity_external_wordpress_assessment_document_with_slug(
            profile,
            "vendor/plugin.php",
        )
    }

    #[cfg(all(feature = "scanning", feature = "wordpress-review"))]
    fn unresolved_identity_external_wordpress_assessment_document_with_slug(
        profile: Option<WordPressComparisonProfile>,
        source_slug: &str,
    ) -> AssessmentDocument<'static> {
        const FIRST_ID: &str = "00000000-0000-4000-8000-000000000001";
        let mut source: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../../docs/examples/wordpress-review/wordfence-v3/production.synthetic.json"
        ))
        .unwrap();
        source[FIRST_ID]["software"][0]["slug"] = serde_json::Value::String(source_slug.to_owned());
        let encoded = serde_json::to_vec(&source).unwrap();
        let catalog =
            crate::wordpress_review::parse_wordfence_v3_production(encoded.as_slice()).unwrap();
        let context = profile.map(|_| {
            crate::wordpress_review::parse_wordpress_context(
                br#"{
                  "schema":"security.wordpress-context/v1",
                  "root":"https://example.test/",
                  "components":[
                    {"kind":"plugin","slug":"termivar-fixture-component","version":"1.0"}
                  ]
                }"#,
            )
            .unwrap()
        });
        let inputs = crate::wordpress_review::WordPressReviewInputs::new(context, None)
            .with_wordfence_v3_catalog(catalog)
            .unwrap();
        let inputs = if let Some(profile) = profile {
            inputs.with_external_version_profile(profile).unwrap()
        } else {
            inputs
        };
        let signals = [
            crate::wordpress_review::WordPressComponentSignal::same_origin_asset(
                WordPressComponentKind::Plugin,
                "termivar-fixture-component",
            )
            .unwrap(),
        ];
        let result = crate::wordpress_review::evaluate_wordpress_review(&signals, &inputs).unwrap();

        let mut document = profile.map_or_else(external_wordpress_assessment_document, |profile| {
            explicitly_profiled_external_wordpress_assessment_document(profile)
        });
        let audit = document.wordpress_review.as_mut().unwrap();
        audit.schema = "security.wordpress-review-audit/v6";
        audit.external_review = Some(wordpress_external_review_document(
            result.external_review().unwrap(),
        ));
        document
    }

    #[cfg(feature = "scanning")]
    #[test]
    fn assessment_json_schema_is_additive_minimized_and_linkage_preserving() {
        let document = complete_assessment_document();
        let rendered =
            render_assessment_with_limit(&document, ReportFormat::Json, usize::MAX).unwrap();
        let value: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(value["schema"], ASSESSMENT_REPORT_DOCUMENT_SCHEMA);
        assert_eq!(
            value["source_schema"],
            crate::web_runtime::ASSESSMENT_RUN_REPORT_SCHEMA
        );
        assert_eq!(value["run_schema"], termivar_core::RUN_REPORT_SCHEMA);
        assert_eq!(value["profile_schema"], "venom.scan-profile/v1");
        assert_eq!(value["profile"], "web-review");
        assert_eq!(value["status"], "complete");
        assert_eq!(value["subject_count"], 1);
        assert_eq!(value["item_count"], 3);
        assert_eq!(value["items"][0]["disposition"], "informational");
        assert_eq!(value["items"][0]["claim_basis"], "observation");
        assert_eq!(
            value["items"][0]["evidence_references"],
            serde_json::json!(["evidence-0000"])
        );
        assert_eq!(value["items"][1]["disposition"], "needs_review");
        assert_eq!(value["items"][1]["claim_basis"], "differential");
        assert_eq!(
            value["items"][1]["control_evidence_references"],
            serde_json::json!(["evidence-0001"])
        );
        assert_eq!(
            value["items"][1]["candidate_evidence_references"],
            serde_json::json!(["evidence-0002"])
        );
        assert_eq!(value["items"][2]["disposition"], "confirmed");
        assert_eq!(value["items"][2]["claim_basis"], "verifier_transition");
        assert_eq!(value["items"][2]["case_reference"], "case-0000");
        assert_eq!(value["items"][2]["outcome_reference"], "outcome-0000");
        assert_eq!(value["items"][2]["verification_stage"], "active");
        assert!(!rendered.contains(REPORT_DOCUMENT_SCHEMA));
        for forbidden_key in [
            "target",
            "authorized_origin",
            "body",
            "headers",
            "cookie",
            "authorization",
            "case_id",
            "outcome_id",
            "verifier_rule_id",
        ] {
            assert!(value.get(forbidden_key).is_none());
        }
    }

    #[cfg(feature = "scanning")]
    #[test]
    fn assessment_dispositions_claim_bases_and_opaque_links_are_visible_in_every_format() {
        let document = complete_assessment_document();
        for format in ReportGenerator::available_formats() {
            let rendered = render_assessment_with_limit(&document, *format, usize::MAX).unwrap();
            for token in [
                "informational",
                "needs_review",
                "confirmed",
                "observation",
                "differential",
                "verifier_transition",
                "evidence-0000",
                "evidence-0001",
                "evidence-0002",
                "evidence-0003",
                "evidence-0004",
                "case-0000",
                "outcome-0000",
                "active",
            ] {
                assert!(rendered.contains(token), "{format:?} omitted {token}");
            }
        }
    }

    #[cfg(all(feature = "scanning", feature = "authorization-review"))]
    #[test]
    fn absent_authorization_audit_adds_no_wire_field_row_or_section() {
        let document = complete_assessment_document();
        assert!(document.authorization_review.is_none());

        let json = render_assessment_with_limit(&document, ReportFormat::Json, usize::MAX).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed.get("authorization_review").is_none());

        let csv = render_assessment_with_limit(&document, ReportFormat::Csv, usize::MAX).unwrap();
        assert!(!csv.contains("authorization_review_audit"));

        let html = render_assessment_with_limit(&document, ReportFormat::Html, usize::MAX).unwrap();
        assert!(!html.contains("Resource authorization review audit"));

        let markdown =
            render_assessment_with_limit(&document, ReportFormat::Markdown, usize::MAX).unwrap();
        assert!(!markdown.contains("Resource authorization review audit"));
    }

    #[cfg(all(feature = "scanning", feature = "openapi-review"))]
    #[test]
    fn openapi_reporting_absent_audit_adds_no_wire_field_row_or_section() {
        let document = complete_assessment_document();
        assert!(document.openapi_review.is_none());

        let json = render_assessment_with_limit(&document, ReportFormat::Json, usize::MAX).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed.get("openapi_review").is_none());

        let csv = render_assessment_with_limit(&document, ReportFormat::Csv, usize::MAX).unwrap();
        assert!(!csv.contains("openapi_review_audit"));

        let html = render_assessment_with_limit(&document, ReportFormat::Html, usize::MAX).unwrap();
        assert!(!html.contains("OpenAPI review audit"));

        let markdown =
            render_assessment_with_limit(&document, ReportFormat::Markdown, usize::MAX).unwrap();
        assert!(!markdown.contains("OpenAPI review audit"));
    }

    #[cfg(all(feature = "scanning", feature = "openapi-review"))]
    #[test]
    fn openapi_reporting_positive_audit_is_minimized_and_redacted_in_every_format() {
        let document = observed_openapi_assessment_document();
        let json = render_assessment_with_limit(&document, ReportFormat::Json, usize::MAX).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let audit = parsed["openapi_review"].as_object().unwrap();
        assert_eq!(audit["outcome"], "document_observed");
        assert_eq!(audit["request_count"], 2);
        assert_eq!(audit["active_verification_count"], 1);
        assert_eq!(audit["item_projected"], true);
        let audit_keys = audit
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        let expected_audit_keys = [
            "schema",
            "capability_id",
            "outcome",
            "candidate_source",
            "request_count",
            "active_verification_count",
            "version",
            "semantic_digest",
            "path_count",
            "operation_count",
            "get_operation_count",
            "write_operation_count",
            "path_parameter_count",
            "query_parameter_count",
            "explicit_auth_operation_count",
            "anonymous_operation_count",
            "url_like_operation_count",
            "multipart_operation_count",
            "deprecated_operation_count",
            "replay_matched",
            "item_projected",
        ]
        .into_iter()
        .collect();
        assert_eq!(audit_keys, expected_audit_keys);
        for forbidden_key in [
            "document",
            "raw_document",
            "server",
            "servers",
            "example",
            "examples",
            "request",
            "response",
            "headers",
            "cookies",
            "authorization",
        ] {
            assert!(!audit.contains_key(forbidden_key));
        }

        for format in ReportGenerator::available_formats() {
            let rendered = render_assessment_with_limit(&document, *format, usize::MAX).unwrap();
            assert!(rendered.contains(OPENAPI_REVIEW_CAPABILITY_ID));
            assert!(rendered.contains("document_observed"));
            for sentinel in [
                "RAW-OPENAPI-DOCUMENT-MUST-NOT-LEAK-4E5A91",
                "https://private-openapi-server.example.test/secret",
                "OPENAPI-EXAMPLE-VALUE-MUST-NOT-LEAK-13C8D7",
                "Bearer OPENAPI-AUTH-MUST-NOT-LEAK-98A02F",
                "session=OPENAPI-COOKIE-MUST-NOT-LEAK-79BD10",
            ] {
                assert!(!rendered.contains(sentinel), "{format:?} leaked {sentinel}");
            }
        }
    }

    #[cfg(all(feature = "scanning", feature = "openapi-review"))]
    #[test]
    fn openapi_reporting_outcome_tokens_are_exhaustive_and_stable() {
        for (outcome, token) in [
            (OpenApiRuntimeOutcome::NotEligible, "not_eligible"),
            (OpenApiRuntimeOutcome::DocumentObserved, "document_observed"),
            (
                OpenApiRuntimeOutcome::Swagger20MetadataOnly,
                "swagger_20_metadata_only",
            ),
            (
                OpenApiRuntimeOutcome::UnsupportedVersion,
                "unsupported_version",
            ),
            (OpenApiRuntimeOutcome::ReplayMismatch, "replay_mismatch"),
            (OpenApiRuntimeOutcome::UnsupportedMedia, "unsupported_media"),
            (OpenApiRuntimeOutcome::Malformed, "malformed"),
            (OpenApiRuntimeOutcome::LimitExceeded, "limit_exceeded"),
            (OpenApiRuntimeOutcome::TooLarge, "too_large"),
            (OpenApiRuntimeOutcome::RedirectObserved, "redirect_observed"),
            (OpenApiRuntimeOutcome::RateLimited, "rate_limited"),
            (
                OpenApiRuntimeOutcome::DefensiveInterference,
                "defensive_interference",
            ),
            (OpenApiRuntimeOutcome::HttpError, "http_error"),
            (OpenApiRuntimeOutcome::Truncated, "truncated"),
            (OpenApiRuntimeOutcome::Incomplete, "incomplete"),
            (OpenApiRuntimeOutcome::BudgetExhausted, "budget_exhausted"),
            (OpenApiRuntimeOutcome::Cancelled, "cancelled"),
        ] {
            assert_eq!(openapi_outcome(outcome), token);
        }
    }

    #[cfg(all(feature = "scanning", feature = "rest-review"))]
    #[test]
    fn rest_reporting_absent_audit_adds_no_wire_field_row_or_section() {
        let document = complete_assessment_document();
        assert!(document.rest_review.is_none());

        let json = render_assessment_with_limit(&document, ReportFormat::Json, usize::MAX).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed.get("rest_review").is_none());

        let csv = render_assessment_with_limit(&document, ReportFormat::Csv, usize::MAX).unwrap();
        assert!(!csv.contains("rest_readonly_review_audit"));

        let html = render_assessment_with_limit(&document, ReportFormat::Html, usize::MAX).unwrap();
        assert!(!html.contains("REST read-only review audit"));

        let markdown =
            render_assessment_with_limit(&document, ReportFormat::Markdown, usize::MAX).unwrap();
        assert!(!markdown.contains("REST read-only review audit"));
    }

    #[cfg(all(feature = "scanning", feature = "rest-review"))]
    #[test]
    fn rest_reporting_positive_audit_is_minimized_and_redacted_in_every_format() {
        let document = observed_rest_assessment_document();
        let json = render_assessment_with_limit(&document, ReportFormat::Json, usize::MAX).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let audit = parsed["rest_review"].as_object().unwrap();
        assert_eq!(audit["schema"], "security.rest-readonly-review-audit/v1");
        assert_eq!(audit["capability_id"], REST_REVIEW_CAPABILITY_ID);
        assert_eq!(audit["enabled"], true);
        assert_eq!(audit["method"], "get");
        assert_eq!(audit["outcome"], "surface_observed");
        assert_eq!(audit["request_count"], 2);
        assert_eq!(audit["active_verification_count"], 1);
        assert_eq!(audit["eligible_operation_count"], 3);
        assert_eq!(audit["documented_response"], "json_compatible");
        assert_eq!(audit["observed_media"], "json_compatible");
        assert_eq!(audit["status_class"], 2);
        assert_eq!(audit["replay_stable"], true);
        assert_eq!(audit["item_projected"], true);
        let keys = audit
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        let expected = [
            "schema",
            "capability_id",
            "enabled",
            "method",
            "outcome",
            "request_count",
            "active_verification_count",
            "eligible_operation_count",
            "selected_operation_identity",
            "documented_response",
            "observed_media",
            "status_class",
            "replay_stable",
            "item_projected",
        ]
        .into_iter()
        .collect();
        assert_eq!(keys, expected);
        for forbidden_key in [
            "url",
            "path",
            "query",
            "body",
            "response",
            "scalar_values",
            "examples",
            "defaults",
            "credentials",
            "server",
        ] {
            assert!(!audit.contains_key(forbidden_key));
        }

        for format in ReportGenerator::available_formats() {
            let rendered = render_assessment_with_limit(&document, *format, usize::MAX).unwrap();
            assert!(rendered.contains(REST_REVIEW_CAPABILITY_ID));
            assert!(rendered.contains("surface_observed"));
            for sentinel in [
                "REST-RAW-PATH-MUST-NOT-LEAK-5C61E8",
                "REST-QUERY-MUST-NOT-LEAK-6A7B20",
                "REST-RESPONSE-BODY-MUST-NOT-LEAK-9073D4",
                "REST-SCALAR-MUST-NOT-LEAK-44B8F1",
                "Bearer REST-AUTH-MUST-NOT-LEAK-A31E09",
                "session=REST-COOKIE-MUST-NOT-LEAK-190AF2",
            ] {
                assert!(!rendered.contains(sentinel), "{format:?} leaked {sentinel}");
            }
        }
    }

    #[cfg(all(feature = "scanning", feature = "rest-review"))]
    #[test]
    fn rest_reporting_contract_rejects_inconsistent_positive_truth() {
        let mut too_many_requests = observed_rest_assessment_document();
        too_many_requests
            .rest_review
            .as_mut()
            .unwrap()
            .request_count = 3;
        let mut no_replay = observed_rest_assessment_document();
        no_replay.rest_review.as_mut().unwrap().replay_stable = false;
        let mut no_audit = observed_rest_assessment_document();
        no_audit.rest_review = None;
        let mut wrong_identity = observed_rest_assessment_document();
        wrong_identity
            .rest_review
            .as_mut()
            .unwrap()
            .selected_operation_identity = Some("raw/path".to_owned());
        let mut wrong_method = observed_rest_assessment_document();
        wrong_method.rest_review.as_mut().unwrap().method = "post";

        for document in [
            too_many_requests,
            no_replay,
            no_audit,
            wrong_identity,
            wrong_method,
        ] {
            for format in ReportGenerator::available_formats() {
                assert_eq!(
                    render_assessment_with_limit(&document, *format, usize::MAX),
                    Err(ReportError::Serialization)
                );
            }
        }
    }

    #[cfg(all(feature = "scanning", feature = "wordpress-review"))]
    #[test]
    fn wordpress_reporting_is_bounded_typed_and_escaped_in_every_format() {
        let document = observed_wordpress_assessment_document();
        let json = render_assessment_with_limit(&document, ReportFormat::Json, usize::MAX).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let audit = &parsed["wordpress_review"];
        assert_eq!(audit["schema"], "security.wordpress-review-audit/v1");
        assert_eq!(audit["capability_id"], WORDPRESS_REVIEW_CAPABILITY_ID);
        assert_eq!(audit["catalog_status"], "evaluated");
        assert_eq!(
            audit["catalog"]["id"],
            "termivar-synthetic-wordpress-reporting"
        );
        assert_eq!(audit["catalog"]["revision"], "synthetic-v1");
        assert_eq!(audit["catalog"]["retrieved_on"], "2026-09-06");
        assert_eq!(audit["signal_count"], 1);
        assert_eq!(audit["evidence_reference_count"], 1);
        assert_eq!(audit["additional_request_count"], 0);
        assert_eq!(audit["item_projected"], true);
        assert_eq!(audit["component_count"], 1);
        assert_eq!(audit["advisory_count"], 1);
        assert_eq!(audit["components"][0]["identity"]["kind"], "core");
        assert_eq!(
            audit["components"][0]["versions"][0]["confidence"],
            "public_declaration"
        );
        assert_eq!(
            audit["advisories"][0]["applicability"],
            "indeterminate_missing_evidence"
        );
        assert_eq!(audit["advisories"][0]["exploit_execution"], "not_performed");
        assert_eq!(audit["advisories"][0]["impact_validation"], "not_performed");
        assert!(audit.get("external_review").is_none());
        assert!(audit["advisories"][0].get("comparison_profile").is_none());
        assert!(audit["advisories"][0].get("version_resolution").is_none());
        assert!(audit["advisories"][0]
            .get("version_resolution_reason")
            .is_none());

        let csv = render_assessment_with_limit(&document, ReportFormat::Csv, usize::MAX).unwrap();
        assert!(csv.contains("wordpress_review_audit"));
        assert!(csv.contains("SYNTHETIC-REPORTING-WORDPRESS-0001"));
        let audit_row = csv
            .lines()
            .find(|line| line.contains("wordpress_review_audit"))
            .unwrap();
        assert_eq!(
            parse_csv_line(audit_row).len(),
            ASSESSMENT_CSV_HEADERS.len()
        );
        let html = render_assessment_with_limit(&document, ReportFormat::Html, usize::MAX).unwrap();
        assert!(html.contains("WordPress evidence review audit"));
        assert!(html.contains("SYNTHETIC-REPORTING-WORDPRESS-0001"));
        assert!(!html.contains("<script>inert()</script>"));
        assert!(html.contains("&lt;script&gt;inert()&lt;/script&gt;"));
        assert!(!html.contains("<script"));
        let markdown =
            render_assessment_with_limit(&document, ReportFormat::Markdown, usize::MAX).unwrap();
        assert!(markdown.contains("WordPress evidence review audit"));
        assert!(markdown.contains("SYNTHETIC-REPORTING-WORDPRESS-0001"));
        assert!(markdown.contains("not_performed"));
    }

    #[cfg(all(feature = "scanning", feature = "wordpress-review"))]
    #[test]
    fn wordpress_discovery_reporting_is_separate_strict_and_reader_compatible() {
        let document = discovered_wordpress_assessment_document();
        let json = render_assessment_with_limit(&document, ReportFormat::Json, usize::MAX).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let discovery = &parsed["wordpress_discovery"];
        assert_eq!(
            parsed["wordpress_review"]["schema"],
            "security.wordpress-review-audit/v7"
        );
        assert_eq!(
            parsed["wordpress_review"]["review_basis_schema"],
            "security.wordpress-review-audit/v1"
        );
        assert_eq!(discovery["schema"], WORDPRESS_DISCOVERY_AUDIT_SCHEMA);
        assert_eq!(discovery["policy_id"], WORDPRESS_DISCOVERY_POLICY_ID);
        assert_eq!(discovery["method"], "get");
        assert_eq!(discovery["credential_mode"], "anonymous");
        assert_eq!(discovery["candidate_limit_reached"], false);
        assert_eq!(discovery["omitted_candidate_count"], 0);
        assert_eq!(discovery["attempted_request_count"], 3);
        assert_eq!(discovery["completed_response_count"], 3);
        assert_eq!(discovery["committed_response_count"], 3);
        assert_eq!(discovery["response_bytes"], 768);
        assert_eq!(discovery["sources"][0]["namespaces"][0], "wp/v2");
        assert_eq!(discovery["sources"][1]["theme"]["version"], "1.2.3");
        assert_eq!(discovery["sources"][2]["plugin"]["stable_tag"], "9.9.9");
        assert_eq!(discovery["sources"][1]["theme"]["requires_php"], "8.1");
        assert_eq!(discovery["sources"][2]["plugin"]["requires_php"], "8.1");
        assert_eq!(
            parsed["wordpress_review"]["additional_request_count"], 3,
            "the discovery-influenced v7 audit must expose actual broker attempts"
        );
        assert!(parsed["wordpress_review"]["components"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|component| component["versions"].as_array().into_iter().flatten())
            .all(|version| version["value"] != "9.9.9"));

        for format in [ReportFormat::Html, ReportFormat::Markdown] {
            let rendered = render_assessment_with_limit(&document, format, usize::MAX).unwrap();
            assert!(rendered.contains(WORDPRESS_DISCOVERY_AUDIT_SCHEMA));
            assert!(rendered.contains("termivar-metadata-lab"));
            assert!(rendered.contains("9.9.9"));
            assert!(rendered.contains("not installed version"));
            assert!(!rendered.contains("confirmed_vulnerability"));
        }
        let csv = render_assessment_with_limit(&document, ReportFormat::Csv, usize::MAX).unwrap();
        assert!(csv.contains("wordpress_discovery_audit"));
        assert!(csv.contains(WORDPRESS_DISCOVERY_AUDIT_SCHEMA));
        assert!(csv.contains("termivar-metadata-lab"));

        let comparison = comparison::compare_reports(
            json.as_bytes(),
            json.as_bytes(),
            comparison::ComparisonFormat::Json,
        )
        .unwrap();
        let comparison: serde_json::Value = serde_json::from_str(&comparison).unwrap();
        assert_eq!(
            comparison["wordpress_review_comparison"]["methodology"]["status"],
            "unchanged"
        );
        assert_eq!(
            comparison["wordpress_review_comparison"]["coverage"]["status"],
            "not_established"
        );
        assert_eq!(comparison["unchanged"].as_array().map(Vec::len), Some(2));
        assert_eq!(comparison["only_in_after"], serde_json::json!([]));
        assert_eq!(comparison["only_in_before"], serde_json::json!([]));
        assert_eq!(comparison["changed"], serde_json::json!([]));

        let mut renumbered: serde_json::Value = serde_json::from_str(&json).unwrap();
        let replacement_references = ["evidence-0101", "evidence-0102", "evidence-0103"];
        for (source, replacement) in renumbered["wordpress_discovery"]["sources"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .zip(replacement_references)
        {
            source["evidence_references"] = serde_json::json!([replacement]);
        }
        let discovery_item = renumbered["items"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|item| item["capability_id"] == WORDPRESS_DISCOVERY_OBSERVATION_CAPABILITY_ID)
            .unwrap();
        discovery_item["evidence_references"] = serde_json::json!(replacement_references);
        let renumbered = serde_json::to_vec(&renumbered).unwrap();
        let renumbering_comparison = comparison::compare_reports(
            json.as_bytes(),
            &renumbered,
            comparison::ComparisonFormat::Json,
        )
        .unwrap();
        let renumbering_comparison: serde_json::Value =
            serde_json::from_str(&renumbering_comparison).unwrap();
        assert_eq!(
            renumbering_comparison["only_in_after"],
            serde_json::json!([])
        );
        assert_eq!(
            renumbering_comparison["only_in_before"],
            serde_json::json!([])
        );
        assert_eq!(renumbering_comparison["changed"], serde_json::json!([]));
        assert_eq!(
            renumbering_comparison["unchanged"].as_array().map(Vec::len),
            Some(2),
            "report-local evidence reference renumbering is not a semantic change"
        );
        assert_eq!(
            renumbering_comparison["wordpress_review_comparison"]["methodology"]["status"],
            "unchanged"
        );
        assert_eq!(
            renumbering_comparison["wordpress_review_comparison"]["coverage"]["status"],
            "not_established"
        );

        let mut review_only_document = observed_wordpress_assessment_document();
        review_only_document.items[0].fingerprint =
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let review_only =
            render_assessment_with_limit(&review_only_document, ReportFormat::Json, usize::MAX)
                .unwrap();
        let collection_change = comparison::compare_reports(
            review_only.as_bytes(),
            json.as_bytes(),
            comparison::ComparisonFormat::Json,
        )
        .unwrap();
        let collection_change: serde_json::Value =
            serde_json::from_str(&collection_change).unwrap();
        assert_eq!(
            collection_change["wordpress_review_comparison"]["methodology"]["status"],
            "changed"
        );
        assert_eq!(
            collection_change["wordpress_review_comparison"]["coverage"]["status"],
            "changed"
        );
        assert_eq!(
            collection_change["only_in_after"]
                .as_array()
                .and_then(|items| items.first())
                .map(|item| &item["capability_id"]),
            Some(&serde_json::json!(
                WORDPRESS_DISCOVERY_OBSERVATION_CAPABILITY_ID
            )),
            "the distinct observation must remain in Report Compare's exhaustive four-group partition"
        );
        assert_eq!(
            collection_change["only_in_before"],
            serde_json::json!([]),
            "absence of discovery must not be labelled remediation"
        );

        let reverse_collection_change = comparison::compare_reports(
            json.as_bytes(),
            review_only.as_bytes(),
            comparison::ComparisonFormat::Json,
        )
        .unwrap();
        let reverse_collection_change: serde_json::Value =
            serde_json::from_str(&reverse_collection_change).unwrap();
        assert_eq!(
            reverse_collection_change["only_in_after"],
            serde_json::json!([])
        );
        assert_eq!(
            reverse_collection_change["only_in_before"]
                .as_array()
                .and_then(|items| items.first())
                .map(|item| &item["capability_id"]),
            Some(&serde_json::json!(
                WORDPRESS_DISCOVERY_OBSERVATION_CAPABILITY_ID
            ))
        );
        assert_eq!(
            reverse_collection_change["wordpress_review_comparison"]["methodology"]["status"],
            "changed"
        );
        assert_eq!(
            reverse_collection_change["wordpress_review_comparison"]["coverage"]["status"],
            "changed"
        );

        let mut invalid: serde_json::Value = serde_json::from_str(&json).unwrap();
        invalid["wordpress_discovery"]["attempted_request_count"] = serde_json::json!(4);
        let invalid = serde_json::to_vec(&invalid).unwrap();
        assert_eq!(
            comparison::import_assessment_summary(&invalid),
            Err(comparison::ComparisonError::InvalidDocument)
        );

        let mut false_commit: serde_json::Value = serde_json::from_str(&json).unwrap();
        false_commit["wordpress_discovery"]["sources"][0]["evidence_reference_count"] =
            serde_json::json!(0);
        assert_eq!(
            comparison::import_assessment_summary(&serde_json::to_vec(&false_commit).unwrap()),
            Err(comparison::ComparisonError::InvalidDocument)
        );

        let mut false_observation: serde_json::Value = serde_json::from_str(&json).unwrap();
        false_observation["wordpress_discovery"]["sources"][0]
            .as_object_mut()
            .unwrap()
            .remove("namespaces");
        assert_eq!(
            comparison::import_assessment_summary(&serde_json::to_vec(&false_observation).unwrap()),
            Err(comparison::ComparisonError::InvalidDocument)
        );

        let mut old_schema_vocabulary_leak: serde_json::Value =
            serde_json::from_str(&json).unwrap();
        old_schema_vocabulary_leak
            .as_object_mut()
            .unwrap()
            .remove("wordpress_discovery");
        let review = old_schema_vocabulary_leak["wordpress_review"]
            .as_object_mut()
            .unwrap();
        review.insert(
            "schema".to_owned(),
            serde_json::json!("security.wordpress-review-audit/v1"),
        );
        review.remove("review_basis_schema");
        review.insert("additional_request_count".to_owned(), serde_json::json!(0));
        assert_eq!(
            comparison::import_assessment_summary(
                &serde_json::to_vec(&old_schema_vocabulary_leak).unwrap()
            ),
            Err(comparison::ComparisonError::InvalidDocument),
            "legacy audit schemas must not accept discovery-only evidence vocabulary"
        );

        let mut false_discovery_confidence: serde_json::Value =
            serde_json::from_str(&json).unwrap();
        let theme = false_discovery_confidence["wordpress_review"]["components"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|component| component["identity"]["slug"] == "termivar-child")
            .unwrap();
        theme["confidence_classes"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!("operator_assertion"));
        assert_eq!(
            comparison::import_assessment_summary(
                &serde_json::to_vec(&false_discovery_confidence).unwrap()
            ),
            Err(comparison::ComparisonError::InvalidDocument)
        );

        let mut missing_basis: serde_json::Value = serde_json::from_str(&json).unwrap();
        missing_basis["wordpress_review"]
            .as_object_mut()
            .unwrap()
            .remove("review_basis_schema");
        assert_eq!(
            comparison::import_assessment_summary(&serde_json::to_vec(&missing_basis).unwrap()),
            Err(comparison::ComparisonError::InvalidDocument)
        );

        let mut mismatched_request_accounting: serde_json::Value =
            serde_json::from_str(&json).unwrap();
        mismatched_request_accounting["wordpress_review"]["additional_request_count"] =
            serde_json::json!(2);
        assert_eq!(
            comparison::import_assessment_summary(
                &serde_json::to_vec(&mismatched_request_accounting).unwrap()
            ),
            Err(comparison::ComparisonError::InvalidDocument)
        );

        let mut invalid_slug: serde_json::Value = serde_json::from_str(&json).unwrap();
        invalid_slug["wordpress_discovery"]["sources"][1]["component"]["slug"] =
            serde_json::json!("../theme");
        assert_eq!(
            comparison::import_assessment_summary(&serde_json::to_vec(&invalid_slug).unwrap()),
            Err(comparison::ComparisonError::InvalidDocument)
        );

        let mut duplicate_source: serde_json::Value = serde_json::from_str(&json).unwrap();
        let duplicate = duplicate_source["wordpress_discovery"]["sources"][1].clone();
        duplicate_source["wordpress_discovery"]["sources"]
            .as_array_mut()
            .unwrap()
            .push(duplicate);
        for field in [
            "candidate_count",
            "attempted_request_count",
            "completed_response_count",
            "committed_response_count",
            "source_count",
        ] {
            duplicate_source["wordpress_discovery"][field] = serde_json::json!(4);
        }
        duplicate_source["wordpress_discovery"]["response_bytes"] = serde_json::json!(1_024);
        duplicate_source["wordpress_review"]["additional_request_count"] = serde_json::json!(4);
        assert_eq!(
            comparison::import_assessment_summary(&serde_json::to_vec(&duplicate_source).unwrap()),
            Err(comparison::ComparisonError::InvalidDocument)
        );

        let mut false_candidate_limit: serde_json::Value = serde_json::from_str(&json).unwrap();
        false_candidate_limit["wordpress_discovery"]["candidate_limit_reached"] =
            serde_json::json!(true);
        assert_eq!(
            comparison::import_assessment_summary(
                &serde_json::to_vec(&false_candidate_limit).unwrap()
            ),
            Err(comparison::ComparisonError::InvalidDocument)
        );

        let mut too_many_theme_requests: serde_json::Value = serde_json::from_str(&json).unwrap();
        for ordinal in 0..3 {
            too_many_theme_requests["wordpress_discovery"]["sources"]
                .as_array_mut()
                .unwrap()
                .push(serde_json::json!({
                    "kind": "theme_stylesheet",
                    "component": {
                        "kind": "theme",
                        "slug": format!("quota-theme-{ordinal}"),
                    },
                    "parent_depth": 1,
                    "outcome": "request_failed",
                    "request_attempted": true,
                    "response_bytes": 0,
                    "evidence_reference_count": 0,
                    "evidence_references": [],
                }));
        }
        too_many_theme_requests["wordpress_discovery"]["candidate_count"] = serde_json::json!(6);
        too_many_theme_requests["wordpress_discovery"]["attempted_request_count"] =
            serde_json::json!(6);
        too_many_theme_requests["wordpress_discovery"]["source_count"] = serde_json::json!(6);
        too_many_theme_requests["wordpress_review"]["additional_request_count"] =
            serde_json::json!(6);
        assert_eq!(
            comparison::import_assessment_summary(
                &serde_json::to_vec(&too_many_theme_requests).unwrap()
            ),
            Err(comparison::ComparisonError::InvalidDocument),
            "the strict reader must reject a reconciled audit above the three-theme request ceiling"
        );

        let mut invalid_producer_slug = discovered_wordpress_assessment_document();
        invalid_producer_slug
            .wordpress_discovery
            .as_mut()
            .unwrap()
            .sources[1]
            .component
            .as_mut()
            .unwrap()
            .slug = "../theme".to_owned();
        assert_eq!(
            render_assessment_with_limit(&invalid_producer_slug, ReportFormat::Json, usize::MAX),
            Err(ReportError::Serialization)
        );

        let mut false_candidate_limit_producer = discovered_wordpress_assessment_document();
        false_candidate_limit_producer
            .wordpress_discovery
            .as_mut()
            .unwrap()
            .candidate_limit_reached = true;
        assert_eq!(
            render_assessment_with_limit(
                &false_candidate_limit_producer,
                ReportFormat::Json,
                usize::MAX
            ),
            Err(ReportError::Serialization)
        );

        let mut too_many_theme_requests_producer = discovered_wordpress_assessment_document();
        let discovery = too_many_theme_requests_producer
            .wordpress_discovery
            .as_mut()
            .unwrap();
        for ordinal in 0..3 {
            discovery.sources.push(WordPressDiscoverySourceDocument {
                kind: "theme_stylesheet",
                component: Some(WordPressComponentIdentityDocument {
                    kind: "theme",
                    slug: format!("quota-theme-{ordinal}"),
                }),
                parent_depth: 1,
                outcome: "request_failed",
                request_attempted: true,
                response_bytes: 0,
                evidence_reference_count: 0,
                evidence_references: Vec::new(),
                namespaces: Vec::new(),
                theme: None,
                plugin: None,
            });
        }
        discovery.candidate_count = 6;
        discovery.attempted_request_count = 6;
        discovery.source_count = 6;
        too_many_theme_requests_producer
            .wordpress_review
            .as_mut()
            .unwrap()
            .additional_request_count = 6;
        assert_eq!(
            render_assessment_with_limit(
                &too_many_theme_requests_producer,
                ReportFormat::Json,
                usize::MAX
            ),
            Err(ReportError::Serialization),
            "the report writer must reject a reconciled audit above the three-theme request ceiling"
        );

        // The broker charges the whole transport-delivered chunk that crosses
        // its two-MiB retention boundary. That chunk has no source-level fixed
        // maximum, so the strict reader validates u64 accounting and exact
        // reconciliation rather than inventing a three-MiB wire ceiling.
        let mut chunk_overrun: serde_json::Value = serde_json::from_str(&json).unwrap();
        let observed = 4_u64 * 1_024 * 1_024;
        chunk_overrun["wordpress_discovery"]["sources"][0]["response_bytes"] =
            serde_json::json!(observed);
        chunk_overrun["wordpress_discovery"]["response_bytes"] = serde_json::json!(observed + 512);
        comparison::import_assessment_summary(&serde_json::to_vec(&chunk_overrun).unwrap())
            .unwrap();
    }

    #[cfg(all(feature = "scanning", feature = "wordpress-review"))]
    #[test]
    fn wordpress_discovery_writer_enforces_component_links_and_runtime_field_bounds() {
        let render = |document: &AssessmentDocument<'_>| {
            render_assessment_with_limit(document, ReportFormat::Json, usize::MAX)
        };

        let mut missing_component = discovered_wordpress_assessment_document();
        let review = missing_component.wordpress_review.as_mut().unwrap();
        review.components.retain(|component| {
            !(component.identity.kind == "plugin"
                && component.identity.slug == "termivar-metadata-lab")
        });
        review.component_count = review.components.len();
        assert_eq!(render(&missing_component), Err(ReportError::Serialization));

        let mut wrong_source_class = discovered_wordpress_assessment_document();
        let component = wrong_source_class
            .wordpress_review
            .as_mut()
            .unwrap()
            .components
            .iter_mut()
            .find(|component| component.identity.slug == "termivar-metadata-lab")
            .unwrap();
        component.identity_sources = vec!["operator_context"];
        component.confidence_classes = vec!["operator_assertion"];
        component.evidence_class = "operator_supplied";
        assert_eq!(render(&wrong_source_class), Err(ReportError::Serialization));

        let mut metadata_at_limit = discovered_wordpress_assessment_document();
        metadata_at_limit
            .wordpress_discovery
            .as_mut()
            .unwrap()
            .sources[2]
            .plugin
            .as_mut()
            .unwrap()
            .name = Some("m".repeat(MAX_WORDPRESS_DISCOVERY_AUDIT_METADATA_BYTES));
        render(&metadata_at_limit).unwrap();
        metadata_at_limit
            .wordpress_discovery
            .as_mut()
            .unwrap()
            .sources[2]
            .plugin
            .as_mut()
            .unwrap()
            .name = Some("m".repeat(MAX_WORDPRESS_DISCOVERY_AUDIT_METADATA_BYTES + 1));
        assert_eq!(render(&metadata_at_limit), Err(ReportError::Serialization));

        let mut version_at_limit = discovered_wordpress_assessment_document();
        let version = "1".repeat(MAX_WORDPRESS_DISCOVERY_AUDIT_VERSION_BYTES);
        version_at_limit
            .wordpress_discovery
            .as_mut()
            .unwrap()
            .sources[1]
            .theme
            .as_mut()
            .unwrap()
            .version = Some(version.clone());
        version_at_limit
            .wordpress_review
            .as_mut()
            .unwrap()
            .components
            .iter_mut()
            .find(|component| component.identity.slug == "termivar-child")
            .unwrap()
            .versions[0]
            .value = version;
        render(&version_at_limit).unwrap();
        let oversized_version = "1".repeat(MAX_WORDPRESS_DISCOVERY_AUDIT_VERSION_BYTES + 1);
        version_at_limit
            .wordpress_discovery
            .as_mut()
            .unwrap()
            .sources[1]
            .theme
            .as_mut()
            .unwrap()
            .version = Some(oversized_version.clone());
        version_at_limit
            .wordpress_review
            .as_mut()
            .unwrap()
            .components
            .iter_mut()
            .find(|component| component.identity.slug == "termivar-child")
            .unwrap()
            .versions[0]
            .value = oversized_version;
        assert_eq!(render(&version_at_limit), Err(ReportError::Serialization));

        let mut namespace_at_limit = discovered_wordpress_assessment_document();
        namespace_at_limit
            .wordpress_discovery
            .as_mut()
            .unwrap()
            .sources[0]
            .namespaces[0] = "n".repeat(MAX_WORDPRESS_DISCOVERY_AUDIT_NAMESPACE_BYTES);
        render(&namespace_at_limit).unwrap();
        namespace_at_limit
            .wordpress_discovery
            .as_mut()
            .unwrap()
            .sources[0]
            .namespaces[0] = "n".repeat(MAX_WORDPRESS_DISCOVERY_AUDIT_NAMESPACE_BYTES + 1);
        assert_eq!(render(&namespace_at_limit), Err(ReportError::Serialization));
    }

    #[cfg(all(feature = "scanning", feature = "wordpress-review"))]
    #[test]
    fn wordpress_discovery_importer_rejects_unlinked_components_and_runtime_bound_overruns() {
        let json = render_assessment_with_limit(
            &discovered_wordpress_assessment_document(),
            ReportFormat::Json,
            usize::MAX,
        )
        .unwrap();
        let valid: serde_json::Value = serde_json::from_str(&json).unwrap();

        let mut unlinked = valid.clone();
        unlinked["wordpress_discovery"]["sources"][2]["component"]["slug"] =
            serde_json::json!("unseen-plugin");
        assert_eq!(
            comparison::import_assessment_summary(&serde_json::to_vec(&unlinked).unwrap()),
            Err(comparison::ComparisonError::InvalidDocument)
        );

        let mut metadata_at_limit = valid.clone();
        metadata_at_limit["wordpress_discovery"]["sources"][2]["plugin"]["name"] =
            serde_json::json!("m".repeat(MAX_WORDPRESS_DISCOVERY_AUDIT_METADATA_BYTES));
        comparison::import_assessment_summary(&serde_json::to_vec(&metadata_at_limit).unwrap())
            .unwrap();
        metadata_at_limit["wordpress_discovery"]["sources"][2]["plugin"]["name"] =
            serde_json::json!("m".repeat(MAX_WORDPRESS_DISCOVERY_AUDIT_METADATA_BYTES + 1));
        assert_eq!(
            comparison::import_assessment_summary(&serde_json::to_vec(&metadata_at_limit).unwrap()),
            Err(comparison::ComparisonError::InvalidDocument)
        );

        let mut version_at_limit = valid.clone();
        let version = "1".repeat(MAX_WORDPRESS_DISCOVERY_AUDIT_VERSION_BYTES);
        version_at_limit["wordpress_discovery"]["sources"][1]["theme"]["version"] =
            serde_json::json!(version);
        version_at_limit["wordpress_review"]["components"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|component| component["identity"]["slug"] == "termivar-child")
            .unwrap()["versions"][0]["value"] = serde_json::json!(version);
        comparison::import_assessment_summary(&serde_json::to_vec(&version_at_limit).unwrap())
            .unwrap();
        let oversized_version = "1".repeat(MAX_WORDPRESS_DISCOVERY_AUDIT_VERSION_BYTES + 1);
        version_at_limit["wordpress_discovery"]["sources"][1]["theme"]["version"] =
            serde_json::json!(oversized_version);
        version_at_limit["wordpress_review"]["components"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|component| component["identity"]["slug"] == "termivar-child")
            .unwrap()["versions"][0]["value"] = serde_json::json!(oversized_version);
        assert_eq!(
            comparison::import_assessment_summary(&serde_json::to_vec(&version_at_limit).unwrap()),
            Err(comparison::ComparisonError::InvalidDocument)
        );

        let mut namespace_at_limit = valid.clone();
        namespace_at_limit["wordpress_discovery"]["sources"][0]["namespaces"][0] =
            serde_json::json!("n".repeat(MAX_WORDPRESS_DISCOVERY_AUDIT_NAMESPACE_BYTES));
        comparison::import_assessment_summary(&serde_json::to_vec(&namespace_at_limit).unwrap())
            .unwrap();
        namespace_at_limit["wordpress_discovery"]["sources"][0]["namespaces"][0] =
            serde_json::json!("n".repeat(MAX_WORDPRESS_DISCOVERY_AUDIT_NAMESPACE_BYTES + 1));
        assert_eq!(
            comparison::import_assessment_summary(
                &serde_json::to_vec(&namespace_at_limit).unwrap()
            ),
            Err(comparison::ComparisonError::InvalidDocument)
        );
    }

    #[cfg(all(feature = "scanning", feature = "wordpress-review"))]
    #[test]
    fn profiled_wordpress_reporting_exposes_method_and_uncertainty_in_every_format() {
        let document = profiled_wordpress_assessment_document();
        let json = render_assessment_with_limit(&document, ReportFormat::Json, usize::MAX).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let advisory = &parsed["wordpress_review"]["advisories"][0];
        assert_eq!(
            parsed["wordpress_review"]["schema"],
            "security.wordpress-review-audit/v2"
        );
        assert_eq!(advisory["comparison_profile"], "php-release-subset/v1");
        assert_eq!(advisory["version_resolution"], "supported_equivalent");
        assert_eq!(
            advisory["version_resolution_reason"],
            "single_supported_version"
        );
        assert_eq!(advisory["version_relation"], "within_declared_range");
        assert_eq!(
            advisory["applicability"],
            "candidate_match_on_declared_facts"
        );
        assert_eq!(advisory["exploit_execution"], "not_performed");
        assert_eq!(advisory["impact_validation"], "not_performed");
        assert!(parsed["wordpress_review"].get("external_review").is_none());

        for format in [
            ReportFormat::Html,
            ReportFormat::Markdown,
            ReportFormat::Csv,
        ] {
            let rendered = render_assessment_with_limit(&document, format, usize::MAX).unwrap();
            assert!(rendered.contains("security.wordpress-review-audit/v2"));
            assert!(rendered.contains("php-release-subset/v1"));
            assert!(rendered.contains("single_supported_version"));
            assert!(rendered.contains("not_performed"));
            assert!(!rendered.contains("confirmed_vulnerability"));
        }
    }

    #[cfg(all(feature = "scanning", feature = "wordpress-review"))]
    #[test]
    fn external_wordpress_reporting_is_source_qualified_and_reader_compatible() {
        let document = external_wordpress_assessment_document();
        let json = render_assessment_with_limit(&document, ReportFormat::Json, usize::MAX).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let audit = &parsed["wordpress_review"];
        let external = &audit["external_review"];
        assert_eq!(audit["schema"], "security.wordpress-review-audit/v4");
        assert_eq!(audit["catalog_status"], "evaluated");
        assert!(audit.get("catalog").is_none());
        assert!(audit.get("catalog_schema").is_none());
        assert!(audit.get("inventory_import").is_none());
        assert_eq!(audit["advisory_count"], 0);
        assert_eq!(audit["advisories"], serde_json::json!([]));
        assert_eq!(external["source_namespace"], "wordfence-intelligence");
        assert_eq!(external["source_format"], "wordfence-v3-production");
        assert_eq!(
            external["mapping_revision"],
            "termivar-wordfence-v3-production/v1"
        );
        assert_eq!(
            external["comparison_policy"],
            "wordfence-v3/source-semantics-unresolved/v1"
        );
        assert_eq!(external["input"]["byte_length"], 3883);
        assert_eq!(
            external["input"]["sha256"],
            "d9ed3140f44ae1e0a3746beb9937de2d829d28c068101120a9104c3349901db7"
        );
        assert!(external["input"]["semantic_sha256"]
            .as_str()
            .is_some_and(valid_lowercase_sha256));
        assert_eq!(external["counts"]["parsed_records"], 2);
        assert_eq!(external["counts"]["software_associations"], 3);
        assert_eq!(external["counts"]["selected_associations"], 1);
        assert_eq!(external["counts"]["evaluable_associations"], 0);
        assert_eq!(external["counts"]["unsupported_associations"], 1);
        assert_eq!(external["counts"]["excluded_associations"], 2);
        for absent in [
            "comparison_profile",
            "policy_selection",
            "source_semantics_assurance",
            "identity_mapping_policy",
            "identity_source_assurance",
            "resource_policy",
        ] {
            assert!(external.get(absent).is_none());
        }
        assert!(external["input"].get("accounted_retained_bytes").is_none());
        for absent in [
            "exact_identity_associations",
            "candidate_identity_associations",
            "ambiguous_identity_associations",
            "unresolved_identity_associations",
            "projected_identity_limitations",
            "unprojected_identity_limitations",
            "within_associations",
            "outside_associations",
            "indeterminate_associations",
            "selected_ranges",
            "evaluated_ranges",
            "containing_ranges",
            "noncontaining_ranges",
            "unsupported_ranges",
            "invalid_ranges",
            "not_evaluated_ranges",
            "partial_range_coverage_associations",
        ] {
            assert!(external["counts"].get(absent).is_none());
        }
        assert_eq!(external["notices"].as_array().unwrap().len(), 1);
        let evaluation = &external["evaluations"][0];
        assert!(evaluation.get("identity_mapping").is_none());
        assert!(evaluation.get("identity_collision_raw_count").is_none());
        assert!(evaluation["key"].get("source_component").is_none());
        assert_eq!(evaluation["key"]["component"]["kind"], "plugin");
        assert_eq!(
            evaluation["key"]["component"]["slug"],
            "termivar-fixture-component"
        );
        assert_eq!(
            evaluation["version_relation"],
            "source_comparison_semantics_unresolved"
        );
        assert_eq!(
            evaluation["version_evidence_resolution"]["status"],
            "missing"
        );
        assert_eq!(
            evaluation["version_evidence_resolution"]["evidence_row_count"],
            0
        );
        assert_eq!(
            evaluation["version_evidence_resolution"]["distinct_spelling_count"],
            0
        );
        assert_eq!(evaluation["applicability"], "indeterminate_unsupported");
        assert!(evaluation.get("range_evaluations").is_none());
        assert!(evaluation.get("version_relation_reason").is_none());
        assert!(evaluation["version_evidence_resolution"]
            .get("semantic_status")
            .is_none());
        assert!(evaluation["version_evidence_resolution"]
            .get("semantic_reason")
            .is_none());
        assert_eq!(
            evaluation["record_reference"],
            "https://example.invalid/termivar/wordfence-v3/fixture-advisory-1"
        );
        assert_eq!(
            evaluation["execution"]["exploit_execution"],
            "not_performed"
        );
        assert_eq!(
            evaluation["execution"]["impact_validation"],
            "not_performed"
        );
        assert!(comparison::import_assessment_summary(json.as_bytes()).is_ok());

        let html = render_assessment_with_limit(&document, ReportFormat::Html, usize::MAX).unwrap();
        assert!(html.contains("<h3>External source attribution</h3>"));
        assert!(html.contains(
            "rel=\"noreferrer noopener\" href=\"https://example.invalid/termivar/wordfence-v3/fixture-advisory-1\">Selected source reference</a>"
        ));
        assert!(html.contains("Synthetic fixture material created for Termivar parser testing."));
        assert!(html.contains("This fictional fixture text may be copied"));
        assert!(html.contains(
            "href=\"https://example.invalid/termivar/wordfence-v3/synthetic-fixture-terms\">License terms</a>"
        ));

        let markdown =
            render_assessment_with_limit(&document, ReportFormat::Markdown, usize::MAX).unwrap();
        assert!(markdown.contains("### External source attribution"));
        assert!(markdown.contains(
            "[Selected source reference](<https://example.invalid/termivar/wordfence-v3/fixture-advisory-1>)"
        ));
        assert!(markdown.contains("#### Rights notices"));
        assert!(markdown.contains(
            "[License terms](<https://example.invalid/termivar/wordfence-v3/synthetic-fixture-terms>)"
        ));

        for format in [
            ReportFormat::Html,
            ReportFormat::Markdown,
            ReportFormat::Csv,
        ] {
            let rendered = render_assessment_with_limit(&document, format, usize::MAX).unwrap();
            for expected in [
                "security.wordpress-review-audit/v4",
                "wordfence-intelligence",
                "source_comparison_semantics_unresolved",
                "indeterminate_unsupported",
                "not_performed",
            ] {
                assert!(rendered.contains(expected), "{format:?} omitted {expected}");
            }
            assert!(!rendered.contains("candidate_match_on_declared_facts"));
            assert!(!rendered.contains("confirmed_vulnerability"));
            for v5_only_label in [
                "Comparison profile",
                "Policy selection",
                "Source comparison semantics assurance",
                "Version-relation reason",
                "Semantic version resolution",
                "Semantic resolution reason",
                "Within-range associations",
                "Outside-range associations",
                "Indeterminate associations",
                "Selected source ranges",
                "Evaluated ranges",
                "Containing ranges",
                "Noncontaining ranges",
                "Unsupported ranges",
                "Invalid ranges",
                "Ranges not evaluated",
                "Qualified partial-range matches",
            ] {
                assert!(
                    !rendered.contains(v5_only_label),
                    "{format:?} changed the v4 presentation with {v5_only_label}"
                );
            }
        }

        for (parsed_records, software_associations, excluded_associations) in
            [(0_usize, 1_usize, 0_usize), (1, 2_049, 2_048)]
        {
            let mut invalid = external_wordpress_assessment_document();
            let counts = &mut invalid
                .wordpress_review
                .as_mut()
                .unwrap()
                .external_review
                .as_mut()
                .unwrap()
                .counts;
            counts.parsed_records = parsed_records;
            counts.software_associations = software_associations;
            counts.excluded_associations = excluded_associations;
            for format in ReportGenerator::available_formats() {
                assert_eq!(
                    render_assessment_with_limit(&invalid, *format, usize::MAX),
                    Err(ReportError::Serialization)
                );
            }
        }
    }

    #[cfg(all(feature = "scanning", feature = "wordpress-review"))]
    #[test]
    fn explicit_external_policy_reporting_is_v5_strict_and_reader_compatible() {
        for (profile, profile_id, relation, reason, applicability, within, outside) in [
            (
                WordPressComparisonProfile::NumericDottedV1,
                "numeric-dotted/v1",
                "within_supported_range_under_selected_policy",
                "containing_range",
                "version_match_under_selected_policy",
                1_u64,
                0_u64,
            ),
            (
                WordPressComparisonProfile::PhpReleaseSubsetV1,
                "php-release-subset/v1",
                "outside_declared_ranges_under_selected_policy",
                "all_ranges_outside",
                "no_version_match_under_selected_policy",
                0,
                1,
            ),
        ] {
            let document = explicitly_profiled_external_wordpress_assessment_document(profile);
            let json =
                render_assessment_with_limit(&document, ReportFormat::Json, usize::MAX).unwrap();
            let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
            let audit = &parsed["wordpress_review"];
            let external = &audit["external_review"];
            assert!(comparison::import_assessment_summary(json.as_bytes()).is_ok());
            let self_comparison = comparison::compare_reports(
                json.as_bytes(),
                json.as_bytes(),
                comparison::ComparisonFormat::Json,
            )
            .unwrap();
            let self_comparison: serde_json::Value =
                serde_json::from_str(&self_comparison).unwrap();
            assert_eq!(
                self_comparison["wordpress_review_comparison"]["status"],
                "compared"
            );
            assert_eq!(
                self_comparison["wordpress_review_comparison"]["advisories"]
                    ["paired_unchanged_count"],
                1
            );
            let evaluation = &external["evaluations"][0];

            assert_eq!(audit["schema"], "security.wordpress-review-audit/v5");
            assert_eq!(
                external["comparison_policy"],
                "termivar.wordfence-v3-explicit-interpretation/v1"
            );
            assert_eq!(external["comparison_profile"], profile_id);
            assert_eq!(external["policy_selection"], "explicit_operator");
            assert_eq!(external["source_semantics_assurance"], "not_established");
            for absent in [
                "identity_mapping_policy",
                "identity_source_assurance",
                "resource_policy",
            ] {
                assert!(external.get(absent).is_none());
            }
            assert!(external["input"].get("accounted_retained_bytes").is_none());
            assert_eq!(external["counts"]["selected_associations"], 1);
            assert_eq!(external["counts"]["evaluable_associations"], 1);
            assert_eq!(external["counts"]["unsupported_associations"], 0);
            assert_eq!(external["counts"]["within_associations"], within);
            assert_eq!(external["counts"]["outside_associations"], outside);
            assert_eq!(external["counts"]["indeterminate_associations"], 0);
            assert_eq!(external["counts"]["selected_ranges"], 2);
            assert_eq!(external["counts"]["evaluated_ranges"], 2);
            assert_eq!(external["counts"]["unsupported_ranges"], 0);
            assert_eq!(external["counts"]["invalid_ranges"], 0);
            assert_eq!(external["counts"]["not_evaluated_ranges"], 0);
            assert_eq!(evaluation["version_relation"], relation);
            assert!(evaluation.get("identity_mapping").is_none());
            assert!(evaluation.get("identity_collision_raw_count").is_none());
            assert!(evaluation["key"].get("source_component").is_none());
            assert_eq!(evaluation["version_relation_reason"], reason);
            assert_eq!(evaluation["applicability"], applicability);
            assert_eq!(
                evaluation["version_evidence_resolution"]["semantic_status"],
                "supported_equivalent"
            );
            assert_eq!(
                evaluation["version_evidence_resolution"]["semantic_reason"],
                "single_supported_version"
            );
            assert_eq!(evaluation["range_evaluations"].as_array().unwrap().len(), 2);
            assert_eq!(
                evaluation["execution"]["exploit_execution"],
                "not_performed"
            );
            assert_eq!(
                evaluation["execution"]["impact_validation"],
                "not_performed"
            );
            assert!(comparison::import_assessment_summary(json.as_bytes()).is_ok());

            for format in [
                ReportFormat::Html,
                ReportFormat::Markdown,
                ReportFormat::Csv,
            ] {
                let rendered = render_assessment_with_limit(&document, format, usize::MAX).unwrap();
                for expected in [
                    "security.wordpress-review-audit/v5",
                    "termivar.wordfence-v3-explicit-interpretation/v1",
                    profile_id,
                    "explicit_operator",
                    "not_established",
                    relation,
                    reason,
                    applicability,
                    "not_performed",
                ] {
                    assert!(rendered.contains(expected), "{format:?} omitted {expected}");
                }
                assert!(!rendered.contains("confirmed_vulnerability"));
                assert!(!rendered.contains("verified_remediation"));
                assert!(!rendered.contains("Unsupported relevant associations"));
            }
        }

        let mut source_conflict = explicitly_profiled_external_wordpress_assessment_document(
            WordPressComparisonProfile::NumericDottedV1,
        );
        let external = source_conflict
            .wordpress_review
            .as_mut()
            .unwrap()
            .external_review
            .as_mut()
            .unwrap();
        external.counts.within_associations = Some(0);
        external.counts.indeterminate_associations = Some(1);
        external.counts.evaluable_associations = 0;
        external.counts.unsupported_associations = 1;
        let evaluation = &mut external.evaluations[0];
        evaluation.source_patched_versions[0] = "1.1".to_owned();
        evaluation.version_relation = "indeterminate";
        evaluation.version_relation_reason = Some("source_patched_version_within_affected_range");
        evaluation.applicability = "indeterminate";
        let source_conflict_json =
            render_assessment_with_limit(&source_conflict, ReportFormat::Json, usize::MAX).unwrap();
        assert!(source_conflict_json.contains("source_patched_version_within_affected_range"));
        assert!(comparison::import_assessment_summary(source_conflict_json.as_bytes()).is_ok());

        let mut stale_source_conflict = source_conflict;
        stale_source_conflict
            .wordpress_review
            .as_mut()
            .unwrap()
            .external_review
            .as_mut()
            .unwrap()
            .evaluations[0]
            .version_relation_reason = Some("containing_range");
        for format in ReportGenerator::available_formats() {
            assert_eq!(
                render_assessment_with_limit(&stale_source_conflict, *format, usize::MAX),
                Err(ReportError::Serialization)
            );
        }

        let mut invalid_documents = Vec::new();

        let mut invalid = explicitly_profiled_external_wordpress_assessment_document(
            WordPressComparisonProfile::NumericDottedV1,
        );
        invalid
            .wordpress_review
            .as_mut()
            .unwrap()
            .external_review
            .as_mut()
            .unwrap()
            .source_semantics_assurance = Some("established");
        invalid_documents.push(invalid);

        let mut invalid = explicitly_profiled_external_wordpress_assessment_document(
            WordPressComparisonProfile::NumericDottedV1,
        );
        invalid
            .wordpress_review
            .as_mut()
            .unwrap()
            .external_review
            .as_mut()
            .unwrap()
            .evaluations[0]
            .affected_ranges[0]
            .from_version = "9.0".to_owned();
        invalid_documents.push(invalid);

        let mut invalid = explicitly_profiled_external_wordpress_assessment_document(
            WordPressComparisonProfile::NumericDottedV1,
        );
        let range = &mut invalid
            .wordpress_review
            .as_mut()
            .unwrap()
            .external_review
            .as_mut()
            .unwrap()
            .evaluations[0]
            .range_evaluations
            .as_mut()
            .unwrap()[1];
        range.relation = "not_evaluated";
        range.reason = "missing_version_evidence";
        invalid_documents.push(invalid);

        let mut invalid = explicitly_profiled_external_wordpress_assessment_document(
            WordPressComparisonProfile::NumericDottedV1,
        );
        invalid
            .wordpress_review
            .as_mut()
            .unwrap()
            .external_review
            .as_mut()
            .unwrap()
            .counts
            .within_associations = Some(0);
        invalid_documents.push(invalid);

        let mut invalid = explicitly_profiled_external_wordpress_assessment_document(
            WordPressComparisonProfile::NumericDottedV1,
        );
        invalid
            .wordpress_review
            .as_mut()
            .unwrap()
            .external_review
            .as_mut()
            .unwrap()
            .evaluations[0]
            .range_evaluations
            .as_mut()
            .unwrap()[0]
            .reason = "selected_version_outside_bounds";
        invalid_documents.push(invalid);

        let mut invalid = explicitly_profiled_external_wordpress_assessment_document(
            WordPressComparisonProfile::NumericDottedV1,
        );
        invalid
            .wordpress_review
            .as_mut()
            .unwrap()
            .external_review
            .as_mut()
            .unwrap()
            .evaluations[0]
            .applicability = "no_version_match_under_selected_policy";
        invalid_documents.push(invalid);

        for invalid in invalid_documents {
            for format in ReportGenerator::available_formats() {
                assert_eq!(
                    render_assessment_with_limit(&invalid, *format, usize::MAX),
                    Err(ReportError::Serialization)
                );
            }
        }
    }

    #[cfg(all(feature = "scanning", feature = "wordpress-review"))]
    #[test]
    fn source_identity_reporting_is_v6_strict_and_keeps_uncertainty_visible() {
        for profile in [None, Some(WordPressComparisonProfile::NumericDottedV1)] {
            let document = source_identity_external_wordpress_assessment_document(profile, false);
            let json =
                render_assessment_with_limit(&document, ReportFormat::Json, usize::MAX).unwrap();
            let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
            let audit = &parsed["wordpress_review"];
            let external = &audit["external_review"];
            assert_eq!(audit["schema"], "security.wordpress-review-audit/v6");
            assert_eq!(
                external["mapping_revision"],
                WORDFENCE_V3_MAPPING_REVISION_V2
            );
            assert_eq!(
                external["identity_mapping_policy"],
                WORDFENCE_V3_IDENTITY_MAPPING_POLICY
            );
            assert_eq!(external["identity_source_assurance"], "not_established");
            assert_eq!(external["resource_policy"], WORDFENCE_V3_RESOURCE_POLICY_V1);
            assert!(external["input"]["accounted_retained_bytes"]
                .as_u64()
                .is_some_and(|bytes| bytes > 0));
            assert_eq!(external["counts"]["software_associations"], 3);
            assert_eq!(external["counts"]["exact_identity_associations"], 2);
            assert_eq!(external["counts"]["candidate_identity_associations"], 1);
            assert_eq!(external["counts"]["ambiguous_identity_associations"], 0);
            assert_eq!(external["counts"]["unresolved_identity_associations"], 0);
            let evaluation = &external["evaluations"][0];
            assert_eq!(
                evaluation["key"]["source_component"],
                serde_json::json!({
                    "kind": "plugin",
                    "slug": "Termivar-Fixture-Component"
                })
            );
            assert_eq!(evaluation["identity_mapping"], "ascii_case_fold_candidate");
            assert!(evaluation.get("identity_collision_raw_count").is_none());
            if profile.is_some() {
                assert_eq!(evaluation["version_relation"], "indeterminate");
                assert_eq!(
                    evaluation["version_relation_reason"],
                    "identity_mapping_candidate"
                );
                assert_eq!(evaluation["applicability"], "indeterminate");
                assert!(evaluation["range_evaluations"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|range| range["relation"] == "not_evaluated"
                        && range["reason"] == "identity_mapping_candidate"));
                assert!(evaluation["version_evidence_resolution"]
                    .get("semantic_status")
                    .is_none());
            } else {
                assert_eq!(
                    evaluation["version_relation"],
                    "source_comparison_semantics_unresolved"
                );
                assert_eq!(evaluation["applicability"], "indeterminate_unsupported");
                assert!(evaluation.get("range_evaluations").is_none());
            }

            for format in [
                ReportFormat::Html,
                ReportFormat::Markdown,
                ReportFormat::Csv,
            ] {
                let rendered = render_assessment_with_limit(&document, format, usize::MAX).unwrap();
                for expected in [
                    "security.wordpress-review-audit/v6",
                    "Termivar-Fixture-Component",
                    "ascii_case_fold_candidate",
                    "not_established",
                ] {
                    assert!(rendered.contains(expected), "{format:?} omitted {expected}");
                }
                assert!(!rendered.contains("Irrelevant associations excluded"));
                assert!(!rendered.contains("confirmed_vulnerability"));
                assert!(!rendered.contains("verified_remediation"));
            }
        }

        let collision = source_identity_external_wordpress_assessment_document(None, true);
        let json =
            render_assessment_with_limit(&collision, ReportFormat::Json, usize::MAX).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let external = &parsed["wordpress_review"]["external_review"];
        assert_eq!(external["counts"]["software_associations"], 4);
        assert_eq!(external["counts"]["exact_identity_associations"], 3);
        assert_eq!(external["counts"]["candidate_identity_associations"], 0);
        assert_eq!(external["counts"]["ambiguous_identity_associations"], 1);
        let ambiguous = external["evaluations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|evaluation| evaluation["identity_mapping"] == "ascii_case_fold_ambiguous")
            .unwrap();
        assert_eq!(ambiguous["identity_collision_raw_count"], 2);

        const FIRST_ID: &str = "00000000-0000-4000-8000-000000000001";
        let mut expanded_source: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../../docs/examples/wordpress-review/wordfence-v3/production.synthetic.json"
        ))
        .unwrap();
        expanded_source[FIRST_ID]["description"] = serde_json::Value::String("d".repeat(2_049));
        let expanded_bytes = serde_json::to_vec(&expanded_source).unwrap();
        let expanded = external_wordpress_assessment_document_from_bytes(&expanded_bytes);
        let json = render_assessment_with_limit(&expanded, ReportFormat::Json, usize::MAX).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let external = &parsed["wordpress_review"]["external_review"];
        assert!(comparison::import_assessment_summary(json.as_bytes()).is_ok());
        let self_comparison = comparison::compare_reports(
            json.as_bytes(),
            json.as_bytes(),
            comparison::ComparisonFormat::Json,
        )
        .unwrap();
        let self_comparison: serde_json::Value = serde_json::from_str(&self_comparison).unwrap();
        assert_eq!(
            self_comparison["wordpress_review_comparison"]["advisories"]["paired_unchanged_count"],
            1
        );
        assert_eq!(
            parsed["wordpress_review"]["schema"],
            "security.wordpress-review-audit/v6"
        );
        assert_eq!(external["mapping_revision"], WORDFENCE_V3_MAPPING_REVISION);
        assert_eq!(external["resource_policy"], WORDFENCE_V3_RESOURCE_POLICY_V2);
        assert_eq!(external["counts"]["exact_identity_associations"], 3);
        assert_eq!(external["counts"]["candidate_identity_associations"], 0);
        assert_eq!(external["evaluations"][0]["identity_mapping"], "exact");
        assert_eq!(
            external["evaluations"][0]["key"]["source_component"]["slug"],
            "termivar-fixture-component"
        );

        let mut opaque_source: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../../docs/examples/wordpress-review/wordfence-v3/production.synthetic.json"
        ))
        .unwrap();
        opaque_source[FIRST_ID]["researchers"] =
            serde_json::json!(["Synthetic Researcher", "Synthetic Researcher"]);
        opaque_source[FIRST_ID]["software"][0]["affected_versions"]["[1.0.0, 1.2.3]"]
            ["to_version"] = serde_json::Value::String("0.1.2 β".to_owned());
        opaque_source[FIRST_ID]["software"][0]["patched_versions"] =
            serde_json::json!(["44.0 (17-08-2023)"]);
        let opaque_bytes = serde_json::to_vec(&opaque_source).unwrap();
        let opaque = external_wordpress_assessment_document_from_bytes(&opaque_bytes);
        let opaque_json =
            render_assessment_with_limit(&opaque, ReportFormat::Json, usize::MAX).unwrap();
        let opaque_parsed: serde_json::Value = serde_json::from_str(&opaque_json).unwrap();
        let opaque_evaluation = &opaque_parsed["wordpress_review"]["external_review"]
            ["evaluations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|evaluation| evaluation["key"]["upstream_id"] == FIRST_ID)
            .unwrap();
        assert_eq!(
            opaque_evaluation["researchers"],
            serde_json::json!(["Synthetic Researcher", "Synthetic Researcher"])
        );
        assert_eq!(
            opaque_evaluation["affected_ranges"][0]["to_version"],
            "0.1.2 β"
        );
        assert_eq!(
            opaque_evaluation["source_patched_versions"],
            serde_json::json!(["44.0 (17-08-2023)"])
        );
        assert!(comparison::import_assessment_summary(opaque_json.as_bytes()).is_ok());
        assert!(comparison::compare_reports(
            opaque_json.as_bytes(),
            opaque_json.as_bytes(),
            comparison::ComparisonFormat::Json,
        )
        .is_ok());

        let mut duplicate_researcher_under_v1 =
            source_identity_external_wordpress_assessment_document(None, false);
        duplicate_researcher_under_v1
            .wordpress_review
            .as_mut()
            .unwrap()
            .external_review
            .as_mut()
            .unwrap()
            .evaluations[0]
            .researchers = vec!["Synthetic Researcher".to_owned(); 2];
        let mut opaque_version_under_v1 =
            source_identity_external_wordpress_assessment_document(None, false);
        opaque_version_under_v1
            .wordpress_review
            .as_mut()
            .unwrap()
            .external_review
            .as_mut()
            .unwrap()
            .evaluations[0]
            .affected_ranges[0]
            .to_version = "0.1.2 β".to_owned();
        for invalid in [duplicate_researcher_under_v1, opaque_version_under_v1] {
            assert_eq!(
                render_assessment_with_limit(&invalid, ReportFormat::Json, usize::MAX),
                Err(ReportError::Serialization)
            );
        }

        let mut wrong_mapping = source_identity_external_wordpress_assessment_document(None, false);
        wrong_mapping
            .wordpress_review
            .as_mut()
            .unwrap()
            .external_review
            .as_mut()
            .unwrap()
            .evaluations[0]
            .identity_mapping = Some("exact");
        let mut false_decision = source_identity_external_wordpress_assessment_document(
            Some(WordPressComparisonProfile::NumericDottedV1),
            false,
        );
        let external = false_decision
            .wordpress_review
            .as_mut()
            .unwrap()
            .external_review
            .as_mut()
            .unwrap();
        external.counts.evaluable_associations = 1;
        external.counts.unsupported_associations = 0;
        external.counts.outside_associations = Some(1);
        external.counts.indeterminate_associations = Some(0);
        let evaluation = &mut external.evaluations[0];
        evaluation.version_relation = "outside_declared_ranges_under_selected_policy";
        evaluation.version_relation_reason = Some("all_ranges_outside");
        evaluation.applicability = "no_version_match_under_selected_policy";
        for invalid in [wrong_mapping, false_decision] {
            for format in ReportGenerator::available_formats() {
                assert_eq!(
                    render_assessment_with_limit(&invalid, *format, usize::MAX),
                    Err(ReportError::Serialization)
                );
            }
        }
    }

    #[cfg(all(feature = "scanning", feature = "wordpress-review"))]
    #[test]
    fn unresolved_external_identities_remain_visible_strict_and_comparable() {
        let document = unresolved_identity_external_wordpress_assessment_document(Some(
            WordPressComparisonProfile::NumericDottedV1,
        ));
        let json = render_assessment_with_limit(&document, ReportFormat::Json, usize::MAX).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let external = &parsed["wordpress_review"]["external_review"];
        assert_eq!(external["counts"]["software_associations"], 3);
        assert_eq!(external["counts"]["unresolved_identity_associations"], 1);
        assert_eq!(external["counts"]["projected_identity_limitations"], 1);
        assert_eq!(external["counts"]["unprojected_identity_limitations"], 0);
        assert_eq!(external["counts"]["mapped_unselected_associations"], 2);
        assert_eq!(external["counts"]["excluded_associations"], 3);
        assert_eq!(external["evaluations"].as_array().unwrap().len(), 0);
        let limitation = &external["identity_limitations"][0];
        assert_eq!(
            limitation["key"]["source_component"],
            serde_json::json!({"kind":"plugin","slug":"vendor/plugin.php"})
        );
        assert_eq!(
            limitation["identity_resolution"],
            "canonical_identity_unavailable"
        );
        assert_eq!(limitation["version_relation"], "not_evaluated");
        assert_eq!(
            limitation["version_relation_reason"],
            "canonical_identity_unavailable"
        );
        assert_eq!(limitation["applicability"], "indeterminate");
        assert!(limitation["range_evaluations"]
            .as_array()
            .unwrap()
            .iter()
            .all(|range| range["relation"] == "not_evaluated"
                && range["reason"] == "canonical_identity_unavailable"));
        assert!(comparison::import_assessment_summary(json.as_bytes()).is_ok());

        for slug in ["valid-plugin", "Valid-Plugin"] {
            let mut invalid = unresolved_identity_external_wordpress_assessment_document(Some(
                WordPressComparisonProfile::NumericDottedV1,
            ));
            invalid
                .wordpress_review
                .as_mut()
                .unwrap()
                .external_review
                .as_mut()
                .unwrap()
                .identity_limitations
                .as_mut()
                .unwrap()[0]
                .key
                .source_component
                .slug = slug.to_owned();
            for format in ReportGenerator::available_formats() {
                assert_eq!(
                    render_assessment_with_limit(&invalid, *format, usize::MAX),
                    Err(ReportError::Serialization),
                    "a mappable source identity must not be projected as unavailable"
                );
            }
        }

        let mut missing_projection = parsed.clone();
        missing_projection["wordpress_review"]["external_review"]["identity_limitations"] =
            serde_json::json!([]);
        let mut false_projection_partition = parsed.clone();
        false_projection_partition["wordpress_review"]["external_review"]["counts"]
            ["unprojected_identity_limitations"] = serde_json::json!(1);
        let mut invalid_raw_identity = parsed.clone();
        invalid_raw_identity["wordpress_review"]["external_review"]["identity_limitations"][0]
            ["key"]["source_component"]["slug"] = serde_json::json!("vendor\nplugin.php");
        let mut false_relation = parsed.clone();
        false_relation["wordpress_review"]["external_review"]["identity_limitations"][0]
            ["version_relation"] =
            serde_json::json!("outside_declared_ranges_under_selected_policy");
        let mut unbound_notice_import = parsed.clone();
        unbound_notice_import["wordpress_review"]["external_review"]["identity_limitations"][0]
            ["notice_ids"] = serde_json::json!([]);
        let mut false_exact_limitation = parsed.clone();
        false_exact_limitation["wordpress_review"]["external_review"]["identity_limitations"][0]
            ["key"]["source_component"]["slug"] = serde_json::json!("valid-plugin");
        let mut false_candidate_limitation = parsed.clone();
        false_candidate_limitation["wordpress_review"]["external_review"]["identity_limitations"]
            [0]["key"]["source_component"]["slug"] = serde_json::json!("Valid-Plugin");
        for invalid in [
            missing_projection,
            false_projection_partition,
            invalid_raw_identity,
            false_relation,
            unbound_notice_import,
            false_exact_limitation,
            false_candidate_limitation,
        ] {
            let encoded = serde_json::to_vec(&invalid).unwrap();
            assert_eq!(
                comparison::import_assessment_summary(&encoded),
                Err(comparison::ComparisonError::InvalidDocument)
            );
        }

        let self_comparison = comparison::compare_reports(
            json.as_bytes(),
            json.as_bytes(),
            comparison::ComparisonFormat::Json,
        )
        .unwrap();
        let self_comparison: serde_json::Value = serde_json::from_str(&self_comparison).unwrap();
        let changes = &self_comparison["wordpress_review_comparison"]["advisories"];
        assert_eq!(changes["paired_unchanged_count"], 1);
        assert_eq!(changes["paired_changed"].as_array().unwrap().len(), 0);

        for format in [ReportFormat::Html, ReportFormat::Markdown] {
            let rendered = render_assessment_with_limit(&document, format, usize::MAX).unwrap();
            for expected in [
                "vendor/plugin.php",
                "canonical_identity_unavailable",
                "not_evaluated",
                "Synthetic fixture guidance",
            ] {
                assert!(rendered.contains(expected), "{format:?} omitted {expected}");
            }
        }

        let renamed = unresolved_identity_external_wordpress_assessment_document_with_slug(
            Some(WordPressComparisonProfile::NumericDottedV1),
            "vendor/renamed.php",
        );
        let renamed_json =
            render_assessment_with_limit(&renamed, ReportFormat::Json, usize::MAX).unwrap();
        let comparison = comparison::compare_reports(
            json.as_bytes(),
            renamed_json.as_bytes(),
            comparison::ComparisonFormat::Json,
        )
        .unwrap();
        let comparison: serde_json::Value = serde_json::from_str(&comparison).unwrap();
        let changes = &comparison["wordpress_review_comparison"]["advisories"];
        assert_eq!(changes["paired_unchanged_count"], 0);
        assert_eq!(changes["only_in_before"].as_array().unwrap().len(), 1);
        assert_eq!(changes["only_in_after"].as_array().unwrap().len(), 1);

        let mut wrong_count = unresolved_identity_external_wordpress_assessment_document(None);
        wrong_count
            .wordpress_review
            .as_mut()
            .unwrap()
            .external_review
            .as_mut()
            .unwrap()
            .counts
            .unresolved_identity_associations = Some(0);
        let mut false_result = unresolved_identity_external_wordpress_assessment_document(None);
        false_result
            .wordpress_review
            .as_mut()
            .unwrap()
            .external_review
            .as_mut()
            .unwrap()
            .identity_limitations
            .as_mut()
            .unwrap()[0]
            .version_relation = "outside_declared_ranges_under_selected_policy";
        let mut unbound_notice = unresolved_identity_external_wordpress_assessment_document(None);
        unbound_notice
            .wordpress_review
            .as_mut()
            .unwrap()
            .external_review
            .as_mut()
            .unwrap()
            .identity_limitations
            .as_mut()
            .unwrap()[0]
            .notice_ids
            .clear();
        for invalid in [wrong_count, false_result, unbound_notice] {
            assert_eq!(
                render_assessment_with_limit(&invalid, ReportFormat::Json, usize::MAX),
                Err(ReportError::Serialization)
            );
        }
    }

    #[cfg(all(feature = "scanning", feature = "wordpress-review"))]
    #[test]
    fn legacy_external_exact_identity_normalizes_for_v6_semantic_comparison() {
        let before = external_wordpress_assessment_document();
        let mut after = external_wordpress_assessment_document();
        let audit = after.wordpress_review.as_mut().unwrap();
        audit.schema = "security.wordpress-review-audit/v6";
        let external = audit.external_review.as_mut().unwrap();
        external.identity_mapping_policy = Some(WORDFENCE_V3_IDENTITY_MAPPING_POLICY);
        external.identity_source_assurance = Some("not_established");
        external.resource_policy = Some(WORDFENCE_V3_RESOURCE_POLICY_V2);
        external.input.accounted_retained_bytes = Some(1);
        external.counts.exact_identity_associations = Some(3);
        external.counts.candidate_identity_associations = Some(0);
        external.counts.ambiguous_identity_associations = Some(0);
        external.counts.unresolved_identity_associations = Some(0);
        external.counts.projected_identity_limitations = Some(0);
        external.counts.unprojected_identity_limitations = Some(0);
        external.counts.mapped_unselected_associations =
            Some(external.counts.excluded_associations);
        external.identity_limitations = Some(Vec::new());
        let source_association_fingerprint = external_fixture_source_association_fingerprint();
        for evaluation in &mut external.evaluations {
            evaluation.identity_mapping = Some("exact");
            evaluation.key.source_component =
                Some(WordPressExternalSourceComponentIdentityDocument {
                    kind: evaluation.key.component.kind,
                    slug: evaluation.key.component.slug.clone(),
                });
            evaluation.key.source_association_fingerprint =
                Some(source_association_fingerprint.clone());
        }
        let before_json =
            render_assessment_with_limit(&before, ReportFormat::Json, usize::MAX).unwrap();
        let after_json =
            render_assessment_with_limit(&after, ReportFormat::Json, usize::MAX).unwrap();
        let comparison = comparison::compare_reports(
            before_json.as_bytes(),
            after_json.as_bytes(),
            comparison::ComparisonFormat::Json,
        )
        .unwrap();
        let comparison: serde_json::Value = serde_json::from_str(&comparison).unwrap();
        let wordpress = &comparison["wordpress_review_comparison"];
        assert_eq!(wordpress["methodology"]["status"], "changed");
        assert_eq!(wordpress["advisories"]["paired_unchanged_count"], 1);
        assert_eq!(
            wordpress["advisories"]["paired_changed"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
    }

    #[cfg(all(feature = "scanning", feature = "wordpress-review"))]
    #[test]
    fn external_source_variants_round_trip_and_compare_under_the_stable_source_key() {
        fn variant_document(
            display_name: &str,
            reverse_source_order: bool,
        ) -> AssessmentDocument<'static> {
            let mut source: serde_json::Value = serde_json::from_slice(include_bytes!(
                "../../../docs/examples/wordpress-review/wordfence-v3/production.synthetic.json"
            ))
            .unwrap();
            let software = source["00000000-0000-4000-8000-000000000001"]["software"]
                .as_array_mut()
                .unwrap();
            let mut variant = software[0].clone();
            variant["name"] = serde_json::Value::String(display_name.to_owned());
            variant["remediation"] =
                serde_json::Value::String("Synthetic alternate declaration guidance.".to_owned());
            software.push(variant);
            if reverse_source_order {
                software.reverse();
            }
            let bytes = serde_json::to_vec(&source).unwrap();
            external_wordpress_assessment_document_from_bytes(&bytes)
        }

        let before = variant_document("[SYNTHETIC] Alternate declaration A", false);
        let reordered = variant_document("[SYNTHETIC] Alternate declaration A", true);
        let after = variant_document("[SYNTHETIC] Alternate declaration B", false);
        let before_json =
            render_assessment_with_limit(&before, ReportFormat::Json, usize::MAX).unwrap();
        let reordered_json =
            render_assessment_with_limit(&reordered, ReportFormat::Json, usize::MAX).unwrap();
        let after_json =
            render_assessment_with_limit(&after, ReportFormat::Json, usize::MAX).unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&before_json).unwrap();
        let external = &parsed["wordpress_review"]["external_review"];
        assert_eq!(
            parsed["wordpress_review"]["schema"],
            "security.wordpress-review-audit/v6"
        );
        assert_eq!(
            external["resource_policy"],
            "termivar.wordfence-v3-bounded-capacity/v2"
        );
        let evaluations = external["evaluations"].as_array().unwrap();
        assert_eq!(evaluations.len(), 2);
        let fingerprints = evaluations
            .iter()
            .map(|evaluation| {
                evaluation["key"]["source_association_fingerprint"]
                    .as_str()
                    .unwrap()
            })
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(fingerprints.len(), 2);

        let mut reordered_wire = parsed.clone();
        let reordered_evaluation =
            &mut reordered_wire["wordpress_review"]["external_review"]["evaluations"][0];
        reordered_evaluation["affected_ranges"]
            .as_array_mut()
            .unwrap()
            .reverse();
        reordered_evaluation["source_patched_versions"]
            .as_array_mut()
            .unwrap()
            .reverse();
        let reordered_wire = serde_json::to_vec(&reordered_wire).unwrap();
        comparison::import_assessment_summary(&reordered_wire).unwrap();

        let mut tampered_fingerprint = parsed.clone();
        let fingerprint = tampered_fingerprint["wordpress_review"]["external_review"]
            ["evaluations"][0]["key"]["source_association_fingerprint"]
            .as_str()
            .unwrap()
            .to_owned();
        let replacement = if fingerprint.ends_with('0') { '1' } else { '0' };
        tampered_fingerprint["wordpress_review"]["external_review"]["evaluations"][0]["key"]
            ["source_association_fingerprint"] = serde_json::Value::String(format!(
            "{}{replacement}",
            &fingerprint[..fingerprint.len() - 1]
        ));
        let tampered_fingerprint = serde_json::to_vec(&tampered_fingerprint).unwrap();
        assert_eq!(
            comparison::import_assessment_summary(&tampered_fingerprint),
            Err(comparison::ComparisonError::InvalidDocument)
        );

        let mut duplicate_range_label = parsed.clone();
        let ranges = duplicate_range_label["wordpress_review"]["external_review"]["evaluations"][0]
            ["affected_ranges"]
            .as_array_mut()
            .unwrap();
        ranges.push(ranges[0].clone());
        let duplicate_range_label = serde_json::to_vec(&duplicate_range_label).unwrap();
        assert_eq!(
            comparison::import_assessment_summary(&duplicate_range_label),
            Err(comparison::ComparisonError::InvalidDocument)
        );

        for candidate in [&before_json, &reordered_json, &after_json] {
            comparison::import_assessment_summary(candidate.as_bytes()).unwrap();
        }
        for same in [&before_json, &reordered_json] {
            let comparison = comparison::compare_reports(
                before_json.as_bytes(),
                same.as_bytes(),
                comparison::ComparisonFormat::Json,
            )
            .unwrap();
            let comparison: serde_json::Value = serde_json::from_str(&comparison).unwrap();
            let advisories = &comparison["wordpress_review_comparison"]["advisories"];
            assert_eq!(advisories["paired_unchanged_count"], 1);
            assert_eq!(advisories["paired_changed"].as_array().unwrap().len(), 0);
            assert_eq!(advisories["only_in_before"].as_array().unwrap().len(), 0);
            assert_eq!(advisories["only_in_after"].as_array().unwrap().len(), 0);
        }

        let comparison = comparison::compare_reports(
            before_json.as_bytes(),
            after_json.as_bytes(),
            comparison::ComparisonFormat::Json,
        )
        .unwrap();
        let comparison: serde_json::Value = serde_json::from_str(&comparison).unwrap();
        let advisories = &comparison["wordpress_review_comparison"]["advisories"];
        assert_eq!(advisories["paired_unchanged_count"], 0);
        assert_eq!(advisories["paired_changed"].as_array().unwrap().len(), 1);
        assert_eq!(advisories["only_in_before"].as_array().unwrap().len(), 0);
        assert_eq!(advisories["only_in_after"].as_array().unwrap().len(), 0);
        assert_eq!(
            advisories["paired_changed"][0]["changed_dimensions"],
            serde_json::json!(["source_association_variants"])
        );

        let discovery_json = render_assessment_with_limit(
            &discovered_wordpress_assessment_document(),
            ReportFormat::Json,
            usize::MAX,
        )
        .unwrap();
        let discovery_document: serde_json::Value = serde_json::from_str(&discovery_json).unwrap();
        let discovery = discovery_document["wordpress_discovery"].clone();
        let discovery_item = discovery_document["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["capability_id"] == WORDPRESS_DISCOVERY_OBSERVATION_CAPABILITY_ID)
            .unwrap()
            .clone();
        let depth_zero_identities = discovery["sources"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|source| source["parent_depth"] == 0 && !source["component"].is_null())
            .map(|source| source["component"].clone())
            .collect::<Vec<_>>();
        assert_eq!(depth_zero_identities.len(), 2);
        let discovery_components = depth_zero_identities
            .iter()
            .map(|identity| {
                let matches = discovery_document["wordpress_review"]["components"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|component| component["identity"] == *identity)
                    .collect::<Vec<_>>();
                assert_eq!(matches.len(), 1);
                matches[0].clone()
            })
            .collect::<Vec<_>>();
        let as_discovery_v7 = |source: &str| {
            let mut value: serde_json::Value = serde_json::from_str(source).unwrap();
            let review = value["wordpress_review"].as_object_mut().unwrap();
            let basis = review["schema"].clone();
            review.insert(
                "schema".to_owned(),
                serde_json::json!("security.wordpress-review-audit/v7"),
            );
            review.insert("review_basis_schema".to_owned(), basis);
            review.insert("additional_request_count".to_owned(), serde_json::json!(3));
            let components = review["components"].as_array_mut().unwrap();
            for discovery_component in &discovery_components {
                assert!(components
                    .iter()
                    .all(|component| { component["identity"] != discovery_component["identity"] }));
                components.push(discovery_component.clone());
            }
            let component_count = components.len();
            review.insert(
                "component_count".to_owned(),
                serde_json::json!(component_count),
            );
            value["wordpress_discovery"] = discovery.clone();
            let items = value["items"].as_array_mut().unwrap();
            items.push(discovery_item.clone());
            value["item_count"] = serde_json::json!(items.len());
            serde_json::to_vec(&value).unwrap()
        };
        let v7_before = as_discovery_v7(&before_json);
        let v7_reordered = as_discovery_v7(&reordered_json);
        let v7_after = as_discovery_v7(&after_json);
        for same in [&v7_before, &v7_reordered] {
            comparison::import_assessment_summary(same).unwrap();
            let comparison =
                comparison::compare_reports(&v7_before, same, comparison::ComparisonFormat::Json)
                    .unwrap();
            let comparison: serde_json::Value = serde_json::from_str(&comparison).unwrap();
            let advisories = &comparison["wordpress_review_comparison"]["advisories"];
            assert_eq!(advisories["paired_unchanged_count"], 1);
            assert_eq!(advisories["paired_changed"], serde_json::json!([]));
        }
        let v7_comparison =
            comparison::compare_reports(&v7_before, &v7_after, comparison::ComparisonFormat::Json)
                .unwrap();
        let v7_comparison: serde_json::Value = serde_json::from_str(&v7_comparison).unwrap();
        let v7_advisories = &v7_comparison["wordpress_review_comparison"]["advisories"];
        assert_eq!(v7_advisories["paired_unchanged_count"], 0);
        assert_eq!(v7_advisories["paired_changed"].as_array().unwrap().len(), 1);
        assert_eq!(
            v7_advisories["paired_changed"][0]["changed_dimensions"],
            serde_json::json!(["source_association_variants"])
        );

        let mut impossible_v1: serde_json::Value = serde_json::from_str(&before_json).unwrap();
        impossible_v1["wordpress_review"]["external_review"]["resource_policy"] =
            serde_json::Value::String(WORDFENCE_V3_RESOURCE_POLICY_V1.to_owned());
        let impossible_v1 = serde_json::to_vec(&impossible_v1).unwrap();
        assert_eq!(
            comparison::import_assessment_summary(&impossible_v1),
            Err(comparison::ComparisonError::InvalidDocument)
        );
    }

    #[cfg(all(feature = "scanning", feature = "wordpress-review"))]
    #[test]
    fn wordpress_human_reports_group_typed_results_without_claim_promotion_or_wire_dump() {
        let cases = [
            (
                observed_wordpress_assessment_document(),
                0_usize,
                1_usize,
                "SYNTHETIC-REPORTING-WORDPRESS-0001",
            ),
            (
                profiled_wordpress_assessment_document(),
                1,
                0,
                "php-release-subset/v1",
            ),
            (
                external_wordpress_assessment_document(),
                0,
                1,
                "wordfence-v3/source-semantics-unresolved/v1",
            ),
        ];

        for (document, candidates, limitations, distinguishing_value) in cases {
            let html =
                render_assessment_with_limit(&document, ReportFormat::Html, usize::MAX).unwrap();
            let markdown =
                render_assessment_with_limit(&document, ReportFormat::Markdown, usize::MAX)
                    .unwrap();

            for rendered in [&html, &markdown] {
                for heading in [
                    "Source and coverage",
                    "Component evidence",
                    "Review candidates",
                    "Contradicted on supplied facts",
                    "Evaluation limitations",
                    "Source-declared remediation information",
                ] {
                    assert!(rendered.contains(heading), "missing {heading}");
                }
                assert!(rendered.contains(distinguishing_value));
                assert!(rendered.contains("not_performed"));
                assert!(!rendered.contains("confirmed_vulnerability"));
                assert!(!rendered.contains("verified_remediation"));
                assert!(!rendered.contains("\"external_review\":"));
                assert!(!rendered.contains("\"advisories\":"));
            }

            assert!(html.contains(&format!(
                "<strong>{candidates}</strong><span>Review candidates</span>"
            )));
            assert!(html.contains(&format!(
                "<strong>{limitations}</strong><span>Evaluation limitations</span>"
            )));
            assert!(markdown.contains(&format!("- Review candidates: `{candidates}`")));
            assert!(markdown.contains(&format!("- Evaluation limitations: `{limitations}`")));
        }
    }

    #[cfg(all(feature = "scanning", feature = "wordpress-review"))]
    #[test]
    fn wordpress_human_grouping_is_mutually_exclusive_ordered_and_deterministic() {
        const ADVISORY_ID: &str = "SYNTHETIC-REPORTING-WORDPRESS-0001";
        let candidate = profiled_wordpress_assessment_document();
        let mut contradicted = profiled_wordpress_assessment_document();
        let contradicted_advisory =
            &mut contradicted.wordpress_review.as_mut().unwrap().advisories[0];
        contradicted_advisory.applicability = "contradicted_by_declared_facts";
        contradicted_advisory.version_relation = "outside_declared_ranges";
        let limitation = observed_wordpress_assessment_document();

        for (document, expected_counts) in [
            (candidate, [1_usize, 0_usize, 0_usize]),
            (contradicted, [0, 1, 0]),
            (limitation, [0, 0, 1]),
        ] {
            for format in [ReportFormat::Html, ReportFormat::Markdown] {
                let rendered = render_assessment_with_limit(&document, format, usize::MAX).unwrap();
                let repeated = render_assessment_with_limit(&document, format, usize::MAX).unwrap();
                assert_eq!(rendered, repeated);

                let heading = |title| match format {
                    ReportFormat::Html => format!("<h3>{title}</h3>"),
                    ReportFormat::Markdown => format!("### {title}\n"),
                    _ => unreachable!(),
                };
                let candidate_heading = rendered.find(&heading("Review candidates")).unwrap();
                let contradicted_heading = rendered
                    .find(&heading("Contradicted on supplied facts"))
                    .unwrap();
                let limitation_heading = rendered.find(&heading("Evaluation limitations")).unwrap();
                let remediation_heading = rendered
                    .find(&heading("Source-declared remediation information"))
                    .unwrap();
                assert!(candidate_heading < contradicted_heading);
                assert!(contradicted_heading < limitation_heading);
                assert!(limitation_heading < remediation_heading);
                assert_eq!(rendered.matches(ADVISORY_ID).count(), 1);
                assert_eq!(rendered.matches("not_performed").count(), 2);

                let advisory = rendered.find(ADVISORY_ID).unwrap();
                let (expected_start, expected_end) = if expected_counts[0] == 1 {
                    (candidate_heading, contradicted_heading)
                } else if expected_counts[1] == 1 {
                    (contradicted_heading, limitation_heading)
                } else {
                    (limitation_heading, remediation_heading)
                };
                assert!(expected_start < advisory && advisory < expected_end);

                for (label, count) in [
                    ("Review candidates", expected_counts[0]),
                    ("Contradicted on supplied facts", expected_counts[1]),
                    ("Evaluation limitations", expected_counts[2]),
                ] {
                    let expected = match format {
                        ReportFormat::Html => {
                            format!("<strong>{count}</strong><span>{label}</span>")
                        },
                        ReportFormat::Markdown => format!("- {label}: `{count}`"),
                        _ => unreachable!(),
                    };
                    assert!(
                        rendered.contains(&expected),
                        "{format:?} omitted {expected}"
                    );
                }
            }
        }
    }

    #[cfg(all(feature = "scanning", feature = "wordpress-review"))]
    #[test]
    fn saved_inventory_human_report_distinguishes_supplied_and_missing_categories() {
        let mut document = saved_inventory_wordpress_assessment_document();
        document
            .wordpress_review
            .as_mut()
            .unwrap()
            .inventory_import
            .as_mut()
            .unwrap()
            .limitations
            .push(WordPressInventoryLimitationDocument {
                declared_name: "synthetic-dropin.php".to_owned(),
                version: Some("1.0".to_owned()),
                status: "drop_in",
                reason: "drop_in_identity_is_not_catalog_slug",
            });
        let html = render_assessment_with_limit(&document, ReportFormat::Html, usize::MAX).unwrap();
        let markdown =
            render_assessment_with_limit(&document, ReportFormat::Markdown, usize::MAX).unwrap();

        for rendered in [&html, &markdown] {
            for expected in [
                "Core inventory",
                "Plugin inventory",
                "Theme inventory",
                "not_supplied",
                "supplied",
                "Saved inventory provenance and limitations",
                "wp_cli_plugins_json",
                "operator_supplied",
                "operator_context",
                "operator_assertion",
                "1.2.3-vendor",
                "Unsupported inventory row",
                "synthetic-dropin.php",
                "drop_in_identity_is_not_catalog_slug",
            ] {
                assert!(rendered.contains(expected), "missing {expected}");
            }
            assert!(!rendered.contains("PRIVATE"));
        }
    }

    #[cfg(all(feature = "scanning", feature = "wordpress-review"))]
    #[test]
    fn external_wordpress_human_report_reconciles_source_counts_and_declared_guidance() {
        let document = external_wordpress_assessment_document();
        for format in [ReportFormat::Html, ReportFormat::Markdown] {
            let rendered = render_assessment_with_limit(&document, format, usize::MAX).unwrap();
            for expected in [
                "Parsed source records",
                "Software associations",
                "Relevant associations",
                "Evaluable associations",
                "Unsupported relevant associations",
                "Irrelevant associations excluded",
                "source_comparison_semantics_unresolved",
                "missing",
                "Source patched flag",
                "Source-declared patched versions",
                "Source-declared remediation",
                "Source-declared CVSS metadata",
                "Source informational classification",
                "Source bibliography",
                "Source researchers",
                "Source notice identifiers",
                "Synthetic Fixture Author",
                "not_performed",
            ] {
                assert!(rendered.contains(expected), "{format:?} missing {expected}");
            }
            assert!(rendered.contains("Evaluations with source guidance"));
            assert!(!rendered.contains("Records with source guidance"));
            assert!(rendered.contains("not an automatic update"));
            assert!(rendered.contains("not confirmed vulnerabilities"));
            assert!(!rendered.contains("eleven verified vulnerabilities"));
            assert_eq!(
                rendered
                    .matches("Synthetic fixture guidance: review a source-declared patched version")
                    .count(),
                1
            );
        }
    }

    #[cfg(all(feature = "scanning", feature = "wordpress-review"))]
    #[test]
    fn wordpress_human_presentation_respects_the_report_output_limit() {
        let document = external_wordpress_assessment_document();
        for format in [ReportFormat::Html, ReportFormat::Markdown] {
            let rendered = render_assessment_with_limit(&document, format, usize::MAX).unwrap();
            assert_eq!(
                render_assessment_with_limit(&document, format, rendered.len()),
                Ok(rendered.clone())
            );
            assert_eq!(
                render_assessment_with_limit(&document, format, rendered.len() - 1),
                Err(ReportError::OutputLimitExceeded {
                    limit: rendered.len() - 1
                })
            );
        }
    }

    #[cfg(all(feature = "scanning", feature = "wordpress-review"))]
    #[test]
    fn external_wordpress_reporting_preserves_parser_accepted_safe_text() {
        const ID: &str = "00000000-0000-4000-8000-000000000001";
        let mut source: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../../docs/examples/wordpress-review/wordfence-v3/production.synthetic.json"
        ))
        .unwrap();
        let record = source[ID].as_object_mut().unwrap();
        record.insert(
            "title".to_owned(),
            serde_json::json!("Synthetic\nreport title"),
        );
        record.insert(
            "description".to_owned(),
            serde_json::json!("Synthetic\tdescription"),
        );
        record["cwe"]["name"] = serde_json::json!("Synthetic\tCWE");
        record["cwe"]["description"] = serde_json::json!("Synthetic\rCWE detail");
        record["cvss"]["vector"] = serde_json::json!("CVSS:3.1/AV:N\n");
        record["researchers"][0] = serde_json::json!("Synthetic\tResearcher");
        let software = record["software"].as_array_mut().unwrap();
        software[0]["name"] = serde_json::json!("Synthetic\tPlugin");
        software[0]["remediation"] = serde_json::json!("Synthetic\rremediation");
        let ranges = software[0]["affected_versions"].as_object_mut().unwrap();
        let range = ranges.remove("[1.0.0, 1.2.3]").unwrap();
        ranges.insert("[1.0.0, 1.2.3]\n".to_owned(), range);

        let bytes = serde_json::to_vec(&source).unwrap();
        let document = external_wordpress_assessment_document_from_bytes(&bytes);
        let rendered =
            render_assessment_with_limit(&document, ReportFormat::Json, usize::MAX).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        let evaluation = &parsed["wordpress_review"]["external_review"]["evaluations"][0];
        assert_eq!(evaluation["title"], "Synthetic\nreport title");
        assert_eq!(evaluation["display_name"], "Synthetic\tPlugin");
        assert_eq!(
            evaluation["affected_ranges"][0]["label"],
            "[1.0.0, 1.2.3]\n"
        );
        assert!(comparison::import_assessment_summary(rendered.as_bytes()).is_ok());

        let html = render_assessment_with_limit(&document, ReportFormat::Html, usize::MAX).unwrap();
        assert!(html.contains("Synthetic\\u{000A}report title"));
        assert!(html.contains("Synthetic\\u{0009}description"));
        assert!(!html.contains("Synthetic\nreport title"));
        assert!(!html.contains("<script"));
        let markdown =
            render_assessment_with_limit(&document, ReportFormat::Markdown, usize::MAX).unwrap();
        assert!(markdown.contains("Synthetic\\u{000A}report title"));
        assert!(markdown.contains("Synthetic\\u{0009}description"));
        assert!(!markdown.contains("Synthetic\nreport title"));

        let mut invalid = parsed;
        invalid["wordpress_review"]["external_review"]["evaluations"][0]["title"] =
            serde_json::json!("control\u{1}character");
        let invalid = serde_json::to_vec(&invalid).unwrap();
        assert!(comparison::import_assessment_summary(&invalid).is_err());
    }

    #[cfg(all(feature = "scanning", feature = "wordpress-review"))]
    #[test]
    fn defiant_notice_renders_the_exact_source_record_link() {
        const ID: &str = "00000000-0000-4000-8000-000000000001";
        const RECORD: &str = "https://www.wordfence.com/threat-intel/vulnerabilities/synthetic-fixture?source=api-test";
        let mut source: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../../docs/examples/wordpress-review/wordfence-v3/production.synthetic.json"
        ))
        .unwrap();
        let record = source[ID].as_object_mut().unwrap();
        record.insert("references".to_owned(), serde_json::json!([RECORD]));
        let copyrights = record["copyrights"].as_object_mut().unwrap();
        let notice = copyrights.remove("termivar_fixture_author").unwrap();
        copyrights.insert("defiant".to_owned(), notice);

        let bytes = serde_json::to_vec(&source).unwrap();
        let document = external_wordpress_assessment_document_from_bytes(&bytes);
        let json = render_assessment_with_limit(&document, ReportFormat::Json, usize::MAX).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            parsed["wordpress_review"]["external_review"]["evaluations"][0]["record_reference"],
            RECORD
        );
        assert!(comparison::import_assessment_summary(json.as_bytes()).is_ok());
        let html = render_assessment_with_limit(&document, ReportFormat::Html, usize::MAX).unwrap();
        assert!(html.contains(&format!("href=\"{RECORD}\">Selected source reference</a>")));
        let markdown =
            render_assessment_with_limit(&document, ReportFormat::Markdown, usize::MAX).unwrap();
        assert!(markdown.contains(&format!("[Selected source reference](<{RECORD}>)")));
    }

    #[cfg(all(feature = "scanning", feature = "wordpress-review"))]
    #[test]
    fn saved_inventory_reporting_is_path_free_versioned_and_reader_compatible() {
        let document = saved_inventory_wordpress_assessment_document();
        let json = render_assessment_with_limit(&document, ReportFormat::Json, usize::MAX).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let audit = &parsed["wordpress_review"];
        assert_eq!(audit["schema"], "security.wordpress-review-audit/v3");
        assert!(audit.get("external_review").is_none());
        assert_eq!(audit["catalog_schema"], WORDPRESS_ADVISORY_CATALOG_SCHEMA);
        assert_eq!(audit["inventory_import"]["component_count"], 1);
        assert_eq!(
            audit["inventory_import"]["inputs"][0]["class"],
            "wp_cli_plugins_json"
        );
        assert_eq!(
            audit["inventory_import"]["inputs"][0]["sha256"],
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
        assert_eq!(audit["components"][1]["inventory_status"], "active");
        assert!(comparison::import_assessment_summary(json.as_bytes()).is_ok());

        for format in [
            ReportFormat::Html,
            ReportFormat::Markdown,
            ReportFormat::Csv,
        ] {
            let rendered = render_assessment_with_limit(&document, format, usize::MAX).unwrap();
            assert!(rendered.contains("security.wordpress-review-audit/v3"));
            assert!(rendered.contains("wp_cli_plugins_json"));
            assert!(!rendered.contains("PRIVATE"));
        }

        let mut missing_inventory = saved_inventory_wordpress_assessment_document();
        missing_inventory
            .wordpress_review
            .as_mut()
            .unwrap()
            .inventory_import = None;
        let mut wrong_digest = saved_inventory_wordpress_assessment_document();
        wrong_digest
            .wordpress_review
            .as_mut()
            .unwrap()
            .inventory_import
            .as_mut()
            .unwrap()
            .inputs[0]
            .sha256 = "A".repeat(64);
        let mut status_without_context = saved_inventory_wordpress_assessment_document();
        let component = &mut status_without_context
            .wordpress_review
            .as_mut()
            .unwrap()
            .components[1];
        component.identity_sources = vec!["same_origin_asset_path"];
        component.confidence_classes = vec!["structural_hint"];

        let mut status_without_inventory_count = saved_inventory_wordpress_assessment_document();
        let audit = status_without_inventory_count
            .wordpress_review
            .as_mut()
            .unwrap();
        audit.components[1].inventory_status = None;
        audit.inventory_import.as_mut().unwrap().component_count = 0;

        let mut status_outside_supplied_category = saved_inventory_wordpress_assessment_document();
        let component = &mut status_outside_supplied_category
            .wordpress_review
            .as_mut()
            .unwrap()
            .components[1];
        component.identity.kind = "theme";
        component.identity.slug = "synthetic-theme".to_owned();

        for document in [
            missing_inventory,
            wrong_digest,
            status_without_context,
            status_without_inventory_count,
            status_outside_supplied_category,
        ] {
            for format in ReportGenerator::available_formats() {
                assert_eq!(
                    render_assessment_with_limit(&document, *format, usize::MAX),
                    Err(ReportError::Serialization)
                );
            }
        }

        let mut combined_observed_and_operator = saved_inventory_wordpress_assessment_document();
        let component = &mut combined_observed_and_operator
            .wordpress_review
            .as_mut()
            .unwrap()
            .components[1];
        component.evidence_class = "observed_hint";
        component.identity_sources = vec!["same_origin_asset_path", "operator_context"];
        component.confidence_classes = vec!["structural_hint", "operator_assertion"];
        component.versions.insert(
            0,
            WordPressVersionEvidenceDocument {
                value: "1.2.3-vendor".to_owned(),
                source: "same_origin_asset_path",
                confidence: "structural_hint",
            },
        );
        let json = render_assessment_with_limit(
            &combined_observed_and_operator,
            ReportFormat::Json,
            usize::MAX,
        )
        .unwrap();
        assert!(comparison::import_assessment_summary(json.as_bytes()).is_ok());
    }

    #[cfg(all(feature = "scanning", feature = "wordpress-review"))]
    #[test]
    fn wordpress_reporting_rejects_inconsistent_audit_truth() {
        let mut extra_request = observed_wordpress_assessment_document();
        extra_request
            .wordpress_review
            .as_mut()
            .unwrap()
            .additional_request_count = 1;
        let mut missing_item = observed_wordpress_assessment_document();
        missing_item
            .wordpress_review
            .as_mut()
            .unwrap()
            .item_projected = false;
        let mut missing_audit = observed_wordpress_assessment_document();
        missing_audit.wordpress_review = None;
        let mut wrong_component_count = observed_wordpress_assessment_document();
        wrong_component_count
            .wordpress_review
            .as_mut()
            .unwrap()
            .component_count = 2;
        let mut missing_catalog = observed_wordpress_assessment_document();
        missing_catalog.wordpress_review.as_mut().unwrap().catalog = None;
        let mut v1_profile_leak = observed_wordpress_assessment_document();
        v1_profile_leak
            .wordpress_review
            .as_mut()
            .unwrap()
            .advisories[0]
            .comparison_profile = Some("numeric-dotted/v1");
        let mut v2_missing_resolution = profiled_wordpress_assessment_document();
        v2_missing_resolution
            .wordpress_review
            .as_mut()
            .unwrap()
            .advisories[0]
            .version_resolution = None;
        let mut v2_contradictory_resolution = profiled_wordpress_assessment_document();
        let advisory = &mut v2_contradictory_resolution
            .wordpress_review
            .as_mut()
            .unwrap()
            .advisories[0];
        advisory.version_resolution = Some("unsupported");
        advisory.version_resolution_reason = Some("single_supported_version");
        let mut v4_missing_external = external_wordpress_assessment_document();
        v4_missing_external
            .wordpress_review
            .as_mut()
            .unwrap()
            .external_review = None;
        let mut v4_native_catalog = external_wordpress_assessment_document();
        v4_native_catalog.wordpress_review.as_mut().unwrap().catalog =
            Some(WordPressCatalogDocument {
                id: "invalid-native-catalog".to_owned(),
                revision: "invalid".to_owned(),
                retrieved_on: "2026-09-07".to_owned(),
            });
        let mut v4_wrong_digest = external_wordpress_assessment_document();
        v4_wrong_digest
            .wordpress_review
            .as_mut()
            .unwrap()
            .external_review
            .as_mut()
            .unwrap()
            .input
            .sha256 = "A".repeat(64);

        for document in [
            extra_request,
            missing_item,
            missing_audit,
            wrong_component_count,
            missing_catalog,
            v1_profile_leak,
            v2_missing_resolution,
            v2_contradictory_resolution,
            v4_missing_external,
            v4_native_catalog,
            v4_wrong_digest,
        ] {
            for format in ReportGenerator::available_formats() {
                assert_eq!(
                    render_assessment_with_limit(&document, *format, usize::MAX),
                    Err(ReportError::Serialization)
                );
            }
        }
    }

    #[cfg(all(feature = "scanning", feature = "wordpress-review"))]
    #[test]
    fn wordpress_reporting_and_import_share_combined_result_bounds() {
        let mut maximum_components = observed_wordpress_assessment_document();
        maximum_components.items[0].fingerprint =
            "sha256:0000000000000000000000000000000000000000000000000000000000000001";
        let audit = maximum_components.wordpress_review.as_mut().unwrap();
        audit.catalog_status = "catalogue_not_supplied";
        audit.catalog = None;
        audit.signal_count = u16::try_from(MAX_WORDPRESS_SIGNALS).unwrap();
        audit.evidence_reference_count = 1;
        audit.advisories.clear();
        audit.advisory_count = 0;
        audit.components = (0..MAX_WORDPRESS_RESULT_COMPONENTS)
            .map(|index| {
                let observed = index < MAX_WORDPRESS_SIGNALS;
                WordPressComponentDocument {
                    identity: WordPressComponentIdentityDocument {
                        kind: "plugin",
                        slug: format!("component-{index:03}"),
                    },
                    evidence_class: if observed {
                        "observed_hint"
                    } else {
                        "operator_supplied"
                    },
                    identity_sources: vec![if observed {
                        "same_origin_asset_path"
                    } else {
                        "operator_context"
                    }],
                    confidence_classes: vec![if observed {
                        "structural_hint"
                    } else {
                        "operator_assertion"
                    }],
                    versions: Vec::new(),
                    activation: None,
                    inventory_status: None,
                }
            })
            .collect();
        audit.component_count = audit.components.len();
        let maximum_components_json = render_assessment_with_limit(
            &maximum_components,
            ReportFormat::Json,
            MAX_RENDERED_REPORT_BYTES,
        )
        .unwrap();
        comparison::import_assessment_summary(maximum_components_json.as_bytes()).unwrap();

        let mut maximum_versions = observed_wordpress_assessment_document();
        maximum_versions.items[0].fingerprint =
            "sha256:0000000000000000000000000000000000000000000000000000000000000001";
        let audit = maximum_versions.wordpress_review.as_mut().unwrap();
        audit.catalog_status = "catalogue_not_supplied";
        audit.catalog = None;
        audit.signal_count = u16::try_from(MAX_WORDPRESS_SIGNALS).unwrap();
        audit.evidence_reference_count = 1;
        audit.advisories.clear();
        audit.advisory_count = 0;
        let mut components = vec![WordPressComponentDocument {
            identity: WordPressComponentIdentityDocument {
                kind: "core",
                slug: "wordpress".to_owned(),
            },
            evidence_class: "conflicting",
            identity_sources: vec!["generator_metadata"],
            confidence_classes: vec!["public_declaration"],
            versions: (0..MAX_WORDPRESS_SIGNALS)
                .map(|index| WordPressVersionEvidenceDocument {
                    value: format!("1.0.{index}"),
                    source: "generator_metadata",
                    confidence: "public_declaration",
                })
                .collect(),
            activation: None,
            inventory_status: None,
        }];
        components.extend(
            (0..MAX_WORDPRESS_RESULT_COMPONENTS - MAX_WORDPRESS_SIGNALS).map(|index| {
                WordPressComponentDocument {
                    identity: WordPressComponentIdentityDocument {
                        kind: "plugin",
                        slug: format!("declared-{index:03}"),
                    },
                    evidence_class: "operator_supplied",
                    identity_sources: vec!["operator_context"],
                    confidence_classes: vec!["operator_assertion"],
                    versions: vec![WordPressVersionEvidenceDocument {
                        value: format!("2.0.{index}"),
                        source: "operator_context",
                        confidence: "operator_assertion",
                    }],
                    activation: None,
                    inventory_status: None,
                }
            }),
        );
        audit.components = components;
        audit.component_count = audit.components.len();
        assert_eq!(
            audit
                .components
                .iter()
                .map(|component| component.versions.len())
                .sum::<usize>(),
            MAX_WORDPRESS_RESULT_VERSION_EVIDENCE
        );
        let maximum_versions_json = render_assessment_with_limit(
            &maximum_versions,
            ReportFormat::Json,
            MAX_RENDERED_REPORT_BYTES,
        )
        .unwrap();
        comparison::import_assessment_summary(maximum_versions_json.as_bytes()).unwrap();
    }

    #[cfg(all(feature = "scanning", feature = "wordpress-review"))]
    #[test]
    fn wordpress_reporting_tokens_are_exhaustive_and_semantically_named() {
        for (kind, token) in [
            (WordPressComponentKind::Core, "core"),
            (WordPressComponentKind::Plugin, "plugin"),
            (WordPressComponentKind::Theme, "theme"),
        ] {
            assert_eq!(wordpress_component_kind(kind), token);
        }
        for (source, token) in [
            (
                WordPressEvidenceSource::GeneratorMetadata,
                "generator_metadata",
            ),
            (
                WordPressEvidenceSource::SameOriginAssetPath,
                "same_origin_asset_path",
            ),
            (
                WordPressEvidenceSource::ThemeStylesheetDeclaration,
                "theme_stylesheet_declaration",
            ),
            (WordPressEvidenceSource::OperatorContext, "operator_context"),
        ] {
            assert_eq!(wordpress_evidence_source(source), token);
        }
        for (confidence, token) in [
            (
                WordPressEvidenceConfidence::PublicDeclaration,
                "public_declaration",
            ),
            (
                WordPressEvidenceConfidence::StructuralHint,
                "structural_hint",
            ),
            (
                WordPressEvidenceConfidence::OperatorAssertion,
                "operator_assertion",
            ),
        ] {
            assert_eq!(wordpress_confidence(confidence), token);
        }
        for (class, token) in [
            (
                WordPressComponentEvidenceClass::ObservedHint,
                "observed_hint",
            ),
            (
                WordPressComponentEvidenceClass::OperatorSupplied,
                "operator_supplied",
            ),
            (WordPressComponentEvidenceClass::Conflicting, "conflicting"),
            (WordPressComponentEvidenceClass::Unknown, "unknown"),
        ] {
            assert_eq!(wordpress_evidence_class(class), token);
        }
        for (relation, token) in [
            (
                WordPressVersionRelation::WithinDeclaredRange,
                "within_declared_range",
            ),
            (
                WordPressVersionRelation::OutsideDeclaredRanges,
                "outside_declared_ranges",
            ),
            (WordPressVersionRelation::Unknown, "unknown"),
            (WordPressVersionRelation::Unsupported, "unsupported"),
        ] {
            assert_eq!(wordpress_version_relation(relation), token);
        }
        for (profile, token) in [
            (
                WordPressComparisonProfile::NumericDottedV1,
                "numeric-dotted/v1",
            ),
            (
                WordPressComparisonProfile::PhpReleaseSubsetV1,
                "php-release-subset/v1",
            ),
        ] {
            assert_eq!(wordpress_comparison_profile(profile), token);
        }
        for (resolution, token) in [
            (WordPressVersionResolution::Missing, "missing"),
            (
                WordPressVersionResolution::SupportedEquivalent,
                "supported_equivalent",
            ),
            (WordPressVersionResolution::Conflicting, "conflicting"),
            (WordPressVersionResolution::Unsupported, "unsupported"),
        ] {
            assert_eq!(wordpress_version_resolution(resolution), token);
        }
        for (reason, token) in [
            (
                WordPressVersionResolutionReason::NoVersionEvidence,
                "no_version_evidence",
            ),
            (
                WordPressVersionResolutionReason::SingleSupportedVersion,
                "single_supported_version",
            ),
            (
                WordPressVersionResolutionReason::EquivalentSupportedVersions,
                "equivalent_supported_versions",
            ),
            (
                WordPressVersionResolutionReason::ConflictingVersionEvidence,
                "conflicting_version_evidence",
            ),
            (
                WordPressVersionResolutionReason::UnsupportedVersionEvidence,
                "unsupported_version_evidence",
            ),
        ] {
            assert_eq!(wordpress_version_resolution_reason(reason), token);
        }
        for (applicability, token) in [
            (
                WordPressApplicability::CandidateMatchOnDeclaredFacts,
                "candidate_match_on_declared_facts",
            ),
            (
                WordPressApplicability::ContradictedByDeclaredFacts,
                "contradicted_by_declared_facts",
            ),
            (
                WordPressApplicability::IndeterminateMissingEvidence,
                "indeterminate_missing_evidence",
            ),
            (
                WordPressApplicability::IndeterminateUnsupported,
                "indeterminate_unsupported",
            ),
        ] {
            assert_eq!(wordpress_applicability(applicability), token);
        }
        assert_eq!(
            wordpress_catalog_status(WordPressCatalogStatus::CatalogNotSupplied),
            "catalogue_not_supplied"
        );
        assert_eq!(
            wordpress_catalog_status(WordPressCatalogStatus::Evaluated),
            "evaluated"
        );
        assert_eq!(
            wordpress_execution(WordPressExecutionStatus::NotPerformed),
            "not_performed"
        );

        for prerequisite in [
            WordPressPrerequisite::HostingOs {
                equals: WordPressHostingOs::Linux,
            },
            WordPressPrerequisite::Multisite {
                equals: WordPressMultisiteState::Enabled,
            },
            WordPressPrerequisite::Activation {
                equals: WordPressActivationState::NetworkActive,
            },
            WordPressPrerequisite::Patch {
                id: "upstream-fix".to_owned(),
                equals: WordPressPatchState::NotApplied,
            },
            WordPressPrerequisite::Unsupported {
                name: "php-runtime".to_owned(),
            },
        ] {
            let document =
                wordpress_prerequisite(&prerequisite, WordPressPrerequisiteOutcome::Unknown);
            assert_eq!(document.outcome, "unknown");
            assert_eq!(document.kind == "patch", document.patch_id.is_some());
        }
        for (outcome, token) in [
            (
                WordPressPrerequisiteOutcome::MatchedOnSuppliedFacts,
                "matched_on_supplied_facts",
            ),
            (
                WordPressPrerequisiteOutcome::ContradictedOnSuppliedFacts,
                "contradicted_on_supplied_facts",
            ),
            (WordPressPrerequisiteOutcome::Unknown, "unknown"),
            (WordPressPrerequisiteOutcome::Unsupported, "unsupported"),
        ] {
            assert_eq!(wordpress_prerequisite_outcome(outcome), token);
        }
        for (activation, token) in [
            (WordPressActivationState::Active, "active"),
            (WordPressActivationState::Inactive, "inactive"),
            (WordPressActivationState::NetworkActive, "network_active"),
            (WordPressActivationState::Unknown, "unknown"),
        ] {
            assert_eq!(wordpress_activation(activation), token);
        }
        for (os, token) in [
            (WordPressHostingOs::Linux, "linux"),
            (WordPressHostingOs::Windows, "windows"),
            (WordPressHostingOs::Macos, "macos"),
            (WordPressHostingOs::Bsd, "bsd"),
            (WordPressHostingOs::Other, "other"),
        ] {
            assert_eq!(wordpress_hosting_os(os), token);
        }
        for (state, token) in [
            (WordPressMultisiteState::Enabled, "enabled"),
            (WordPressMultisiteState::Disabled, "disabled"),
        ] {
            assert_eq!(wordpress_multisite(state), token);
        }
        for (state, token) in [
            (WordPressPatchState::Applied, "applied"),
            (WordPressPatchState::NotApplied, "not_applied"),
            (WordPressPatchState::Unknown, "unknown"),
        ] {
            assert_eq!(wordpress_patch(state), token);
        }
    }

    #[cfg(all(feature = "scanning", feature = "rest-review"))]
    #[test]
    fn rest_reporting_outcome_and_class_tokens_are_exhaustive_and_stable() {
        for (outcome, token) in [
            (RestRuntimeOutcome::NotEligible, "not_eligible"),
            (RestRuntimeOutcome::SurfaceObserved, "surface_observed"),
            (RestRuntimeOutcome::ReplayMismatch, "replay_mismatch"),
            (RestRuntimeOutcome::CompleteNonJson, "complete_non_json"),
            (RestRuntimeOutcome::Redirect, "redirect"),
            (
                RestRuntimeOutcome::AuthenticationRequired,
                "authentication_required",
            ),
            (RestRuntimeOutcome::Forbidden, "forbidden"),
            (RestRuntimeOutcome::NotFound, "not_found"),
            (RestRuntimeOutcome::RateLimited, "rate_limited"),
            (
                RestRuntimeOutcome::DefensiveInterference,
                "defensive_interference",
            ),
            (RestRuntimeOutcome::ServerError, "server_error"),
            (RestRuntimeOutcome::UnsupportedMedia, "unsupported_media"),
            (RestRuntimeOutcome::Truncated, "truncated"),
            (RestRuntimeOutcome::Incomplete, "incomplete"),
            (RestRuntimeOutcome::Cancelled, "cancelled"),
            (RestRuntimeOutcome::BudgetExhausted, "budget_exhausted"),
        ] {
            assert_eq!(rest_outcome(outcome), token);
        }
        assert_eq!(
            rest_documented_response(RestDocumentedResponseClass::JsonCompatible),
            "json_compatible"
        );
        assert_eq!(
            rest_documented_response(RestDocumentedResponseClass::Unknown),
            "unknown"
        );
        for (media, token) in [
            (RestObservedMediaClass::JsonCompatible, "json_compatible"),
            (RestObservedMediaClass::Text, "text"),
            (RestObservedMediaClass::Unsupported, "unsupported"),
            (RestObservedMediaClass::Unknown, "unknown"),
        ] {
            assert_eq!(rest_observed_media(media), token);
        }
    }

    #[cfg(feature = "scanning")]
    #[test]
    fn assessment_confirmed_linkage_fails_closed_when_incomplete_or_mismatched() {
        let mut missing_outcome = complete_assessment_document();
        missing_outcome.items[2].outcome_reference = None;
        let mut downgraded_basis = complete_assessment_document();
        downgraded_basis.items[2].claim_basis = "observation";
        let mut cross_basis_evidence = complete_assessment_document();
        cross_basis_evidence.items[1].candidate_evidence_references =
            vec!["evidence-0001".to_owned()];
        for document in [missing_outcome, downgraded_basis, cross_basis_evidence] {
            for format in ReportGenerator::available_formats() {
                assert_eq!(
                    render_assessment_with_limit(&document, *format, usize::MAX),
                    Err(ReportError::Serialization)
                );
            }
        }
    }

    #[cfg(feature = "scanning")]
    #[test]
    fn assessment_renderers_escape_controls_bidi_html_markdown_and_csv_formulae() {
        const HOSTILE: &str = " \t=2+3,<script>alert(`x`)</script>&'\u{202E}\n# injected";
        let document = observation_assessment_document(HOSTILE);

        let json = render_assessment_with_limit(&document, ReportFormat::Json, usize::MAX).unwrap();
        assert!(!json.contains('\t'));
        assert!(!json.contains('\u{202E}'));
        assert!(!json.contains('\n'));
        assert!(json.contains("\\u202E"));
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["items"][0]["title"], HOSTILE);

        let html = render_assessment_with_limit(&document, ReportFormat::Html, usize::MAX).unwrap();
        assert!(!html.contains("<script>"));
        assert!(!html.contains('\u{202E}'));
        assert!(html.contains("&lt;script&gt;"));
        assert!(html.contains("\\u{202E}\\u{000A}"));

        let markdown =
            render_assessment_with_limit(&document, ReportFormat::Markdown, usize::MAX).unwrap();
        assert!(!markdown.contains("\n# injected"));
        assert!(!markdown.contains('\u{202E}'));
        assert!(markdown.contains("\\u{202E}\\u{000A}# injected"));

        let csv = render_assessment_with_limit(&document, ReportFormat::Csv, usize::MAX).unwrap();
        assert!(!csv.contains('\t'));
        assert!(!csv.contains('\u{202E}'));
        assert!(!csv.contains("\n# injected"));
        assert!(csv.contains("' \\u{0009}=2+3"));
        let rows: Vec<Vec<String>> = csv.lines().map(parse_csv_line).collect();
        assert_eq!(rows[0].len(), ASSESSMENT_CSV_HEADERS.len());
        assert!(rows
            .iter()
            .all(|row| row.len() == ASSESSMENT_CSV_HEADERS.len()));
    }

    #[cfg(feature = "scanning")]
    #[test]
    fn assessment_output_ceiling_is_shared_byte_exact_and_returns_no_partial_document() {
        let document = complete_assessment_document();
        for format in ReportGenerator::available_formats() {
            let rendered = render_assessment_with_limit(&document, *format, usize::MAX).unwrap();
            assert_eq!(
                render_assessment_with_limit(&document, *format, rendered.len()).unwrap(),
                rendered
            );
            assert_eq!(
                render_assessment_with_limit(&document, *format, rendered.len() - 1),
                Err(ReportError::OutputLimitExceeded {
                    limit: rendered.len() - 1
                })
            );
        }

        let oversized = "x".repeat(MAX_RENDERED_REPORT_BYTES + 1);
        let document = observation_assessment_document(&oversized);
        assert_eq!(
            render_assessment_with_limit(
                &document,
                ReportFormat::Markdown,
                MAX_RENDERED_REPORT_BYTES
            ),
            Err(ReportError::OutputLimitExceeded {
                limit: MAX_RENDERED_REPORT_BYTES
            })
        );
    }

    #[cfg(feature = "scanning")]
    #[test]
    fn assessment_documents_never_emit_secret_or_raw_runtime_sentinels() {
        let document = complete_assessment_document();
        for format in ReportGenerator::available_formats() {
            let rendered = render_assessment_with_limit(&document, *format, usize::MAX).unwrap();
            for sentinel in [
                "Bearer secret-sentinel",
                "session=secret-sentinel",
                "cookie-value-sentinel",
                "csrf-value-sentinel",
                "https://private.example.test/secret/path",
                "raw-response-body-sentinel",
                "private-evidence-id-sentinel",
                "private-case-id-sentinel",
                "private-outcome-id-sentinel",
                "private-verifier-id-sentinel",
            ] {
                assert!(!rendered.contains(sentinel));
            }
        }
    }

    #[test]
    fn public_format_metadata_and_order_are_stable() {
        assert_eq!(
            ReportGenerator::available_formats(),
            &[
                ReportFormat::Json,
                ReportFormat::Csv,
                ReportFormat::Html,
                ReportFormat::Markdown,
            ]
        );
        let metadata = [
            (ReportFormat::Json, "json", "application/json", "json"),
            (ReportFormat::Csv, "csv", "text/csv; charset=utf-8", "csv"),
            (
                ReportFormat::Html,
                "html",
                "text/html; charset=utf-8",
                "html",
            ),
            (
                ReportFormat::Markdown,
                "markdown",
                "text/markdown; charset=utf-8",
                "md",
            ),
        ];
        for (format, name, media_type, extension) in metadata {
            assert_eq!(format.as_str(), name);
            assert_eq!(format.media_type(), media_type);
            assert_eq!(format.extension(), extension);
        }
    }

    #[test]
    fn lifecycle_statuses_and_stop_codes_render_in_every_format() {
        let cases = [
            (
                RunStatus::Complete,
                RunStopCode::Completed,
                RunStepStatus::Succeeded,
                "complete",
                "completed",
            ),
            (
                RunStatus::Partial,
                RunStopCode::StepFailed,
                RunStepStatus::Failed,
                "partial",
                "step_failed",
            ),
            (
                RunStatus::Cancelled,
                RunStopCode::Cancelled,
                RunStepStatus::Cancelled,
                "cancelled",
                "cancelled",
            ),
            (
                RunStatus::Failed,
                RunStopCode::RuntimeFailed,
                RunStepStatus::Failed,
                "failed",
                "runtime_failed",
            ),
        ];
        for (status, stop_code, step_status, status_token, stop_token) in cases {
            let steps = vec![RunStepReport::new(1, "scan.observe", step_status, 1, None).unwrap()];
            let report = report_for_status(status, stop_code, steps, "target", "summary");
            for format in ReportGenerator::available_formats() {
                let rendered = ReportGenerator::generate(&report, *format).unwrap();
                assert!(rendered.contains(status_token));
                assert!(rendered.contains(stop_token));
            }
        }
    }

    #[test]
    fn non_complete_lifecycle_is_prominent_in_human_formats() {
        let report = report_for_status(
            RunStatus::Partial,
            RunStopCode::StepFailed,
            vec![RunStepReport::new(1, "scan.observe", RunStepStatus::Failed, 1, None).unwrap()],
            "target",
            "summary",
        );
        let html = ReportGenerator::generate(&report, ReportFormat::Html).unwrap();
        assert!(
            html.contains("<aside class=\"lifecycle\">") && html.contains("Run did not complete")
        );
        let markdown = ReportGenerator::generate(&report, ReportFormat::Markdown).unwrap();
        assert!(markdown.contains("> **Lifecycle notice:** This run did not complete."));
    }

    #[test]
    fn json_projection_has_exact_metadata_and_minimized_outcome_shape() {
        let report = complete_report("https://example.test/path", "redacted summary");
        let rendered = ReportGenerator::generate(&report, ReportFormat::Json).unwrap();
        let value: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(value["schema"], REPORT_DOCUMENT_SCHEMA);
        assert_eq!(value["source_schema"], termivar_core::RUN_REPORT_SCHEMA);
        assert_eq!(value["status"], "complete");
        assert_eq!(value["stop_code"], "completed");
        assert_eq!(value["target"], "https://example.test/path");
        assert_eq!(value["authorized_origin"], "https://example.test");
        assert_eq!(value["started_at"], "2026-08-20T10:00:00+00:00");
        assert_eq!(value["completed_at"], "2026-08-20T10:00:01+00:00");
        assert_eq!(
            value["accounting"]["requests"],
            serde_json::json!({"mode":"metered","limit":"10","consumed":"4","remaining":"6"})
        );
        assert_eq!(
            value["steps"][0],
            serde_json::json!({
                "ordinal":1,
                "action_id":"scan.observe",
                "status":"succeeded",
                "duration_ms":"25"
            })
        );
        assert_eq!(
            value["outcomes"][0],
            serde_json::json!({
                "kind":"verification_outcome",
                "action_id":"scan.observe",
                "severity":"info",
                "disposition":"success",
                "confidence_ppm":812345,
                "evidence_count":1,
                "redacted_summary":"redacted summary"
            })
        );
    }

    #[test]
    fn unresolved_observation_kind_is_distinct() {
        let unresolved = RunOutcomeRecord::unresolved(
            EntityId::new(PRIVATE_SUBJECT).unwrap(),
            "scan.observe",
            PRIVATE_RATIONALE,
            "summary",
        )
        .unwrap();
        let input = RunReportInput::new(
            RunStatus::Complete,
            RunStopReason::new(RunStopCode::Completed, "done").unwrap(),
            "target",
            "origin",
            "2026-08-20T10:00:00Z".parse().unwrap(),
            "2026-08-20T10:00:01Z".parse().unwrap(),
        )
        .unwrap()
        .with_steps(vec![RunStepReport::new(
            1,
            "scan.observe",
            RunStepStatus::Succeeded,
            1,
            None,
        )
        .unwrap()])
        .with_outcomes(vec![unresolved]);
        let report = RunReport::new(input).unwrap();
        let rendered = ReportGenerator::generate(&report, ReportFormat::Json).unwrap();
        let value: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(value["outcomes"][0]["kind"], "unresolved_observation");
        assert_eq!(value["outcomes"][0]["confidence_ppm"], 0);
        assert_eq!(value["outcomes"][0]["evidence_count"], 0);
    }

    #[test]
    fn private_source_fields_never_cross_any_renderer() {
        let report = complete_report("target", "public redacted summary");
        let source_fingerprint = report.outcomes()[0].fingerprint().to_owned();
        let forbidden = [
            PRIVATE_SUBJECT,
            PRIVATE_EVIDENCE,
            PRIVATE_RATIONALE,
            PRIVATE_CASE,
            PRIVATE_RULE,
            PRIVATE_HYPOTHESIS,
            PRIVATE_STEP_DETAIL,
            "private-stop-detail-sentinel",
            "evidence_ids",
            "rationale",
        ];
        for format in ReportGenerator::available_formats() {
            let rendered = ReportGenerator::generate(&report, *format).unwrap();
            assert!(!rendered.contains(&source_fingerprint));
            assert!(!rendered.to_ascii_lowercase().contains("fingerprint"));
            for sentinel in forbidden {
                assert!(!rendered.contains(sentinel));
            }
        }
    }

    #[test]
    fn html_is_self_contained_csp_guarded_and_contextually_escaped() {
        let hostile = "<script>alert(\"x\")</script>&'\u{202E}\n";
        let report = complete_report(hostile, hostile);
        let html = ReportGenerator::generate(&report, ReportFormat::Html).unwrap();
        assert!(html.starts_with("<!doctype html>"));
        assert!(html.contains("default-src 'none'"));
        assert!(html.contains("style-src 'unsafe-inline'"));
        assert!(!html.contains("<script>"));
        assert!(!html.contains("src=\"http"));
        assert!(!html.contains("href="));
        assert!(html.contains("&lt;script&gt;"));
        assert!(html.contains("&quot;x&quot;"));
        assert!(html.contains("&amp;&#39;\\u{202E}\\u{000A}"));
    }

    #[test]
    fn markdown_uses_dynamic_code_spans_for_all_untrusted_text() {
        let hostile = "`` </code> [link](https://attacker.test) ![image](x)\n# injected";
        let report = complete_report(hostile, hostile);
        let markdown = ReportGenerator::generate(&report, ReportFormat::Markdown).unwrap();
        assert!(markdown.contains(
            "``` `` </code> [link](https://attacker.test) ![image](x)\\u{000A}# injected ```"
        ));
        assert!(!markdown.contains("\n# injected"));
        assert!(!markdown.lines().any(|line| line.starts_with('<')));
    }

    #[test]
    fn csv_quotes_every_cell_neutralizes_formulas_and_visualizes_controls() {
        let hostile = " \t=2+3,\"quoted\"\u{202E}\nnext";
        let report = complete_report(hostile, hostile);
        let csv = ReportGenerator::generate(&report, ReportFormat::Csv).unwrap();
        for line in csv.lines() {
            assert!(line.starts_with('"'));
            assert!(line.ends_with('"'));
        }
        assert!(csv.contains("\"' \\u{0009}=2+3,\"\"quoted\"\"\\u{202E}\\u{000A}next\""));
        assert!(!csv.contains('\t'));
        assert!(!csv.contains('\u{202E}'));
        assert!(!csv.contains("\nnext"));
        for prefix in ['=', '+', '-', '@'] {
            let value = format!(" \t{prefix}payload");
            let mut output = RenderBuffer::new(1_024);
            write_csv_cell(&mut output, &value).unwrap();
            assert!(output.finish().starts_with("\"' \\u{0009}"));
        }
    }

    #[test]
    fn csv_rows_match_header_width_and_step_named_columns() {
        let report = complete_report("target,\"quoted\"", "summary,\"quoted\"");
        let csv = ReportGenerator::generate(&report, ReportFormat::Csv).unwrap();
        let rows: Vec<Vec<String>> = csv.lines().map(parse_csv_line).collect();
        let headers = &rows[0];
        assert_eq!(headers.len(), CSV_HEADERS.len());
        for row in &rows[1..] {
            assert_eq!(row.len(), headers.len(), "CSV row width drifted: {row:?}");
        }

        let column = |name: &str| headers.iter().position(|header| header == name).unwrap();
        let step = rows
            .iter()
            .find(|row| row[column("record_type")] == "step")
            .unwrap();
        assert_eq!(step[column("action_id")], "scan.observe");
        assert_eq!(step[column("duration_ms")], "25");
        assert_eq!(step[column("status_or_disposition")], "succeeded");
        assert_eq!(step[column("severity")], "");
        assert_eq!(step[column("redacted_summary")], "");
    }

    #[test]
    fn visible_encodings_are_injective_for_markers_backslashes_and_bidi() {
        let render_csv_cell = |value: &str| {
            let mut output = RenderBuffer::new(1_024);
            write_csv_cell(&mut output, value).unwrap();
            output.finish()
        };
        let formula = render_csv_cell("=1+1");
        let literal_apostrophe = render_csv_cell("'=1+1");
        assert_eq!(formula, "\"'=1+1\"");
        assert_eq!(literal_apostrophe, "\"\\u{0027}=1+1\"");
        assert_ne!(formula, literal_apostrophe);

        let actual_bidi_csv = render_csv_cell("\u{202E}");
        let literal_bidi_csv = render_csv_cell("\\u{202E}");
        assert_eq!(actual_bidi_csv, "\"\\u{202E}\"");
        assert_eq!(literal_bidi_csv, "\"\\\\u{202E}\"");
        assert_ne!(actual_bidi_csv, literal_bidi_csv);

        let render_html_text = |value: &str| {
            let mut output = RenderBuffer::new(1_024);
            write_html_text(&mut output, value).unwrap();
            output.finish()
        };
        assert_eq!(render_html_text("\u{202E}"), "\\u{202E}");
        assert_eq!(render_html_text("\\u{202E}"), "\\\\u{202E}");

        assert_eq!(visible_text("\u{202E}"), "\\u{202E}");
        assert_eq!(visible_text("\\u{202E}"), "\\\\u{202E}");
    }

    #[test]
    fn json_escapes_bidi_and_c1_controls_with_parsed_semantics_unchanged() {
        let payload = "actual:\u{202E}:c1:\u{0085}:literal:\\u{202E}";
        let report = complete_report(payload, payload);
        let document = ReportDocument::from_report(&report).unwrap();
        let raw = serde_json::to_string(&document).unwrap();
        let rendered = render_with_limit(&document, ReportFormat::Json, usize::MAX).unwrap();

        assert!(rendered.len() > raw.len());
        assert!(!rendered.contains('\u{202E}'));
        assert!(!rendered.contains('\u{0085}'));
        assert!(rendered.contains("\\u202E"));
        assert!(rendered.contains("\\u0085"));

        let parsed: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(parsed["target"], payload);
        assert_eq!(parsed["outcomes"][0]["redacted_summary"], payload);
        assert_eq!(
            render_with_limit(&document, ReportFormat::Json, rendered.len()).unwrap(),
            rendered
        );
        assert_eq!(
            render_with_limit(&document, ReportFormat::Json, rendered.len() - 1),
            Err(ReportError::OutputLimitExceeded {
                limit: rendered.len() - 1
            })
        );
    }

    #[test]
    fn maximum_u64_values_are_decimal_strings_and_deterministic() {
        let report = maximum_accounting_report();
        let maximum = u64::MAX.to_string();
        let json = ReportGenerator::generate(&report, ReportFormat::Json).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["accounting"]["requests"]["limit"], maximum);
        assert_eq!(value["accounting"]["requests"]["consumed"], maximum);
        assert_eq!(
            value["accounting"]["response_body_bytes"]["consumed"],
            maximum
        );
        assert_eq!(
            value["accounting"]["request_body_bytes"]["remaining"],
            maximum
        );
        assert_eq!(value["steps"][0]["duration_ms"], maximum);
        assert!(value["steps"][0]["duration_ms"].is_string());

        for format in ReportGenerator::available_formats() {
            let first = ReportGenerator::generate(&report, *format).unwrap();
            let second = ReportGenerator::generate(&report, *format).unwrap();
            assert_eq!(first, second);
            assert!(first.contains(&maximum));
        }
    }

    #[test]
    fn markdown_empty_and_all_space_code_spans_are_unambiguous() {
        let render = |value: &str| {
            let mut output = RenderBuffer::new(1_024);
            write_markdown_code_span(&mut output, value).unwrap();
            output.finish()
        };
        assert_eq!(render(""), "`\\u{EMPTY}`");
        assert_eq!(render(" "), "` `");
        assert_eq!(render("   "), "`   `");
        assert_eq!(render("\\u{EMPTY}"), "`\\\\u{EMPTY}`");
        assert_ne!(render(""), render("\\u{EMPTY}"));
    }

    #[test]
    fn output_limit_is_applied_after_escape_expansion_without_partial_return() {
        let report = complete_report("<&", "summary");
        let document = ReportDocument::from_report(&report).unwrap();
        let full_html = render_with_limit(&document, ReportFormat::Html, usize::MAX).unwrap();
        let exact = render_with_limit(&document, ReportFormat::Html, full_html.len()).unwrap();
        assert_eq!(exact, full_html);
        assert_eq!(
            render_with_limit(&document, ReportFormat::Html, full_html.len() - 1),
            Err(ReportError::OutputLimitExceeded {
                limit: full_html.len() - 1
            })
        );

        let escaped_target_offset = full_html.find("&lt;&amp;").unwrap();
        let raw_boundary = escaped_target_offset + "<&".len();
        assert_eq!(
            render_with_limit(&document, ReportFormat::Html, raw_boundary),
            Err(ReportError::OutputLimitExceeded {
                limit: raw_boundary
            })
        );
    }

    #[test]
    fn json_cap_and_utf8_boundaries_are_byte_exact() {
        let report = complete_report("é", "雪");
        let document = ReportDocument::from_report(&report).unwrap();
        let full = render_with_limit(&document, ReportFormat::Json, usize::MAX).unwrap();
        assert!(full.chars().count() < full.len());
        assert!(full.contains("é"));
        assert!(full.contains("雪"));
        assert_eq!(
            render_with_limit(&document, ReportFormat::Json, full.len() - 1),
            Err(ReportError::OutputLimitExceeded {
                limit: full.len() - 1
            })
        );
        assert_eq!(
            render_with_limit(&document, ReportFormat::Json, full.len()).unwrap(),
            full
        );
    }

    #[test]
    fn every_format_is_byte_deterministic_with_stable_envelopes() {
        let report = complete_report("target", "summary");
        let document = ReportDocument::from_report(&report).unwrap();
        for format in ReportGenerator::available_formats() {
            let first = ReportGenerator::generate(&report, *format).unwrap();
            let second = ReportGenerator::generate(&report, *format).unwrap();
            assert_eq!(first.as_bytes(), second.as_bytes());
            assert!(first.len() <= MAX_RENDERED_REPORT_BYTES);
            assert_eq!(
                render_with_limit(&document, *format, first.len()).unwrap(),
                first
            );
            assert_eq!(
                render_with_limit(&document, *format, first.len() - 1),
                Err(ReportError::OutputLimitExceeded {
                    limit: first.len() - 1
                })
            );
        }
        let json = ReportGenerator::generate(&report, ReportFormat::Json).unwrap();
        assert!(json.starts_with(
            "{\"schema\":\"venom-rendered-run/v1\",\"source_schema\":\"venom-run/v1\""
        ));
        let csv = ReportGenerator::generate(&report, ReportFormat::Csv).unwrap();
        assert!(csv.starts_with("\"record_type\",\"name\",\"value\""));
        let markdown = ReportGenerator::generate(&report, ReportFormat::Markdown).unwrap();
        assert!(markdown.starts_with("# Termivar run report\n\n- Schema: `venom-rendered-run/v1`"));
    }

    #[test]
    fn error_display_is_opaque_and_bounded() {
        let limit = ReportError::OutputLimitExceeded { limit: 7 }.to_string();
        let serialization = ReportError::Serialization.to_string();
        assert_eq!(limit, "rendered report exceeds the output byte limit");
        assert_eq!(serialization, "rendered report serialization failed");
        assert!(limit.len() < 80);
        assert!(serialization.len() < 80);
        assert!(!limit.contains('7'));
    }
}
