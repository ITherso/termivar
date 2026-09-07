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
    web_runtime::{WebAssessmentWordPressAudit, WORDPRESS_REVIEW_CAPABILITY_ID},
    wordpress_review::{
        WordPressActivationState, WordPressAdvisoryCatalogSchema, WordPressApplicability,
        WordPressCatalogStatus, WordPressComparisonProfile, WordPressComponentEvidenceClass,
        WordPressComponentKind, WordPressEvidenceConfidence, WordPressEvidenceSource,
        WordPressExecutionStatus, WordPressHostingOs, WordPressInventoryCategoryStatus,
        WordPressInventoryEntryStatus, WordPressInventoryLimitationReason,
        WordPressLocalInputClass, WordPressMultisiteState, WordPressPatchState,
        WordPressPrerequisite, WordPressPrerequisiteOutcome, WordPressVersionRelation,
        WordPressVersionResolution, WordPressVersionResolutionReason,
        MAX_WORDPRESS_ADVISORY_RECORDS, MAX_WORDPRESS_RESULT_COMPONENTS,
        MAX_WORDPRESS_RESULT_VERSION_EVIDENCE, MAX_WORDPRESS_SAVED_INVENTORY_BYTES,
        MAX_WORDPRESS_SIGNALS, WORDPRESS_ADVISORY_CATALOG_SCHEMA,
        WORDPRESS_ADVISORY_CATALOG_SCHEMA_V2,
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
h1,h2{line-height:1.2}.meta{display:grid;grid-template-columns:max-content 1fr;gap:.3rem 1rem}\
.item{border:1px solid currentColor;padding:1rem;margin-block:1rem}.item dl{display:grid;grid-template-columns:max-content 1fr;gap:.3rem 1rem}\
.disposition{border:2px solid currentColor;display:inline-block;font-weight:700;padding:.15rem .4rem}\
code{overflow-wrap:anywhere}.empty{font-style:italic}</style></head><body><main>\
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
        for (label, value) in audit.metadata()? {
            output.push_str("<dt>")?;
            write_html_text(&mut output, label)?;
            output.push_str("</dt><dd><code>")?;
            write_html_text(&mut output, &value)?;
            output.push_str("</code></dd>")?;
        }
        output.push_str("</dl></section>")?;
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
        for (label, value) in audit.metadata()? {
            output.push_fmt(format_args!("- {label}: "))?;
            write_markdown_code_span(&mut output, &value)?;
            output.push_char('\n')?;
        }
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
    items: Vec<AssessmentItemDocument<'a>>,
}

#[cfg(feature = "scanning")]
impl<'a> AssessmentDocument<'a> {
    fn from_report(report: &'a AssessmentRunReport) -> Result<Self, ReportError> {
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
            items: report
                .items()
                .iter()
                .map(AssessmentItemDocument::from_item)
                .collect::<Result<Vec<_>, _>>()?,
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
    capability_id: &'static str,
    catalog_status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    catalog_schema: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    catalog: Option<WordPressCatalogDocument>,
    #[serde(skip_serializing_if = "Option::is_none")]
    inventory_import: Option<WordPressInventoryImportDocument>,
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
impl AssessmentWordPressAuditDocument {
    fn from_audit(audit: &WebAssessmentWordPressAudit) -> Self {
        let result = audit.result();
        let profiled = result.catalog_schema() == Some(WordPressAdvisoryCatalogSchema::V2);
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
        Self {
            schema: if inventory_schema {
                "security.wordpress-review-audit/v3"
            } else if profiled {
                "security.wordpress-review-audit/v2"
            } else {
                "security.wordpress-review-audit/v1"
            },
            capability_id: WORDPRESS_REVIEW_CAPABILITY_ID,
            catalog_status: wordpress_catalog_status(result.catalog_status()),
            catalog_schema: if inventory_schema {
                result
                    .catalog_schema()
                    .map(WordPressAdvisoryCatalogSchema::id)
            } else {
                None
            },
            catalog,
            inventory_import,
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
        let catalog_consistent = matches!(
            (self.catalog_status, self.catalog.as_ref()),
            ("catalogue_not_supplied", None) | ("evaluated", Some(_))
        );
        let version_evidence_count = self
            .components
            .iter()
            .try_fold(0_usize, |count, component| {
                count.checked_add(component.versions.len())
            });
        let inventory = self.schema == "security.wordpress-review-audit/v3";
        let profiled = self.schema == "security.wordpress-review-audit/v2"
            || (inventory && self.catalog_schema == Some(WORDPRESS_ADVISORY_CATALOG_SCHEMA_V2));
        let schema_valid = matches!(
            self.schema,
            "security.wordpress-review-audit/v1"
                | "security.wordpress-review-audit/v2"
                | "security.wordpress-review-audit/v3"
        );
        let catalogue_schema_valid = if inventory {
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
        let inventory_valid = match (&self.inventory_import, inventory) {
            (Some(import), true) => import.is_valid(&self.components),
            (None, false) => self
                .components
                .iter()
                .all(|component| component.inventory_status.is_none()),
            _ => false,
        };
        if !schema_valid
            || self.capability_id != WORDPRESS_REVIEW_CAPABILITY_ID
            || !catalog_consistent
            || !catalogue_schema_valid
            || !inventory_valid
            || self.additional_request_count != 0
            || usize::from(self.signal_count) > MAX_WORDPRESS_SIGNALS
            || usize::from(self.evidence_reference_count) > MAX_WORDPRESS_SIGNALS
            || self.component_count != self.components.len()
            || self.component_count > MAX_WORDPRESS_RESULT_COMPONENTS
            || version_evidence_count
                .is_none_or(|count| count > MAX_WORDPRESS_RESULT_VERSION_EVIDENCE)
            || self.advisory_count != self.advisories.len()
            || self.advisory_count > MAX_WORDPRESS_ADVISORY_RECORDS
            || projected > 1
            || self.item_projected != (projected == 1)
            || self.item_projected != (self.signal_count > 0)
            || self.item_projected != (self.evidence_reference_count > 0)
            || ((self.schema == "security.wordpress-review-audit/v2")
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

    fn metadata(&self) -> Result<Vec<(&'static str, String)>, ReportError> {
        Ok(vec![
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
            ("Bounded audit detail", self.wire_json()?),
        ])
    }
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
            capability_id: WORDPRESS_REVIEW_CAPABILITY_ID,
            catalog_status: "evaluated",
            catalog_schema: None,
            catalog: Some(WordPressCatalogDocument {
                id: "termivar-synthetic-wordpress-reporting".to_owned(),
                revision: "synthetic-v1".to_owned(),
                retrieved_on: "2026-09-06".to_owned(),
            }),
            inventory_import: None,
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
    fn saved_inventory_reporting_is_path_free_versioned_and_reader_compatible() {
        let document = saved_inventory_wordpress_assessment_document();
        let json = render_assessment_with_limit(&document, ReportFormat::Json, usize::MAX).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let audit = &parsed["wordpress_review"];
        assert_eq!(audit["schema"], "security.wordpress-review-audit/v3");
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

        for document in [
            extra_request,
            missing_item,
            missing_audit,
            wrong_component_count,
            missing_catalog,
            v1_profile_leak,
            v2_missing_resolution,
            v2_contradictory_resolution,
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
