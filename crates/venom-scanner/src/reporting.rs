//! Deterministic, bounded rendering for validated [`venom_core::RunReport`] values.

#[cfg(feature = "scanning")]
use crate::web_runtime::{
    AssessmentBasis, AssessmentRunReport, AssessmentRunReportError, ScanProfileV1,
    WebAssessmentRunReport,
};
use serde::Serialize;
use std::{error::Error, fmt, io};
use venom_core::{
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
<title>VENOM run report</title><style>\
:root{color-scheme:light dark}body{font:14px/1.5 system-ui,sans-serif;margin:2rem;max-width:90rem}\
h1,h2{line-height:1.2}.lifecycle{border:3px solid currentColor;padding:.8rem;font-size:1.1rem}.meta{display:grid;grid-template-columns:max-content 1fr;gap:.3rem 1rem}\
table{border-collapse:collapse;width:100%;margin-block:1rem 2rem}th,td{border:1px solid currentColor;padding:.35rem;text-align:left;vertical-align:top}\
code{overflow-wrap:anywhere}.empty{font-style:italic}</style></head><body><main>\
<h1>VENOM run report</h1>",
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
    output.push_str("# VENOM run report\n\n")?;
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
<title>VENOM assessment report</title><style>\
:root{color-scheme:light dark}body{font:14px/1.5 system-ui,sans-serif;margin:2rem;max-width:90rem}\
h1,h2{line-height:1.2}.meta{display:grid;grid-template-columns:max-content 1fr;gap:.3rem 1rem}\
.item{border:1px solid currentColor;padding:1rem;margin-block:1rem}.item dl{display:grid;grid-template-columns:max-content 1fr;gap:.3rem 1rem}\
.disposition{border:2px solid currentColor;display:inline-block;font-weight:700;padding:.15rem .4rem}\
code{overflow-wrap:anywhere}.empty{font-style:italic}</style></head><body><main>\
<h1>VENOM assessment report</h1><p><strong>Lifecycle status:</strong> completed typed assessment.</p><dl class=\"meta\">",
    )?;
    for (label, value) in document.metadata() {
        output.push_str("<dt>")?;
        write_html_text(&mut output, label)?;
        output.push_str("</dt><dd><code>")?;
        write_html_text(&mut output, &value)?;
        output.push_str("</code></dd>")?;
    }
    output.push_str("</dl><section><h2>Assessment items</h2>")?;
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
    output.push_str("# VENOM assessment report\n\n")?;
    for (label, value) in document.metadata() {
        output.push_fmt(format_args!("- {label}: "))?;
        write_markdown_code_span(&mut output, &value)?;
        output.push_char('\n')?;
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
        for item in &self.items {
            item.validate()?;
        }
        Ok(())
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
                    let mut evidence_references = Vec::new();
                    evidence_references.push(reference.to_string());
                    return Ok(Self {
                        evidence_references,
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
    fn from_step(step: &'a venom_core::RunStepReport) -> Self {
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
    use venom_core::{
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
            run_schema: venom_core::RUN_REPORT_SCHEMA,
            profile_schema: crate::web_runtime::SCAN_PROFILE_V1_SCHEMA,
            profile: "web-review",
            status: "complete",
            subject_count: 1,
            item_count: 1,
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
        assert_eq!(value["run_schema"], venom_core::RUN_REPORT_SCHEMA);
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
        assert_eq!(value["source_schema"], venom_core::RUN_REPORT_SCHEMA);
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
        assert!(markdown.starts_with("# VENOM run report\n\n- Schema: `venom-rendered-run/v1`"));
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
