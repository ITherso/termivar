# Bounded run-report rendering

The opt-in `reporting` feature is a Preview source-level library contract for
turning an existing typed `RunReport` into a bounded document. It is not a
scanner, verifier, finding generator, persistence layer, or default CLI output
path.

## Runtime scope

| Property | Contract |
| --- | --- |
| Build | Explicit `venom-scanner` feature `reporting` |
| Input | Immutable, constructor-validated `RunReport` |
| Output | `Result<String, ReportError>` selected by `ReportFormat` |
| Bound | At most `MAX_RENDERED_REPORT_BYTES` (16 MiB) on success |
| Schema | `REPORT_DOCUMENT_SCHEMA` is `venom-rendered-run/v1` |
| Repository caller | None |
| Default `venom scan` | Unchanged; does not call this module |
| Storage or delivery | Host-owned and outside this contract |
| Verdict authority | None; the renderer preserves typed report claims |
| Redaction | None; the host must supply pre-redacted projected fields |

Enable the feature for a library host:

```toml
[dependencies]
venom-scanner = { path = "/path/to/reviewed/venom/crates/venom-scanner", default-features = false, features = ["reporting"] }
```

No published package currently represents this remediated source contract.
Pin and review the source checkout used by the path dependency.

Then render a report the host already owns:

```rust,ignore
use venom_scanner::{ReportFormat, ReportGenerator, RunReport};

fn render(report: &RunReport) -> Result<String, venom_scanner::ReportError> {
    ReportGenerator::generate(report, ReportFormat::Json)
}
```

The same input and format produce the same document. Rendering performs no
filesystem or network I/O and does not observe wall-clock time, randomness, or
environment state. It performs format-specific encoding, not redaction: it
copies `target`, `authorized_origin`, and each outcome's `redacted_summary`.
It also copies step and outcome `action_id` strings. The caller must pre-redact
all of those fields and decides whether and where to persist a successful
result.

Format negotiation is stable and available through
`ReportGenerator::available_formats()`:

| Variant | Token | Media type | Extension |
| --- | --- | --- | --- |
| `Json` | `json` | `application/json` | `json` |
| `Csv` | `csv` | `text/csv; charset=utf-8` | `csv` |
| `Html` | `html` | `text/html; charset=utf-8` | `html` |
| `Markdown` | `markdown` | `text/markdown; charset=utf-8` | `md` |

`ReportFormat::as_str`, `media_type`, and `extension` expose those values. A
render can fail with `ReportError::Serialization` or
`ReportError::OutputLimitExceeded`; neither error returns a partial document.

Format safety is part of the v1 document contract. JSON represents accounting
`limit`, `consumed`, and `remaining` values plus step `duration_ms` as decimal
strings so the full `u64` range is portable; control and bidirectional-control
characters use JSON escapes that parse to the original scalar values. CSV
quotes every cell, neutralizes spreadsheet-formula prefixes, and uses
reversible visible escapes for controls and backslashes. HTML and Markdown use
context-specific encoding for every projected text value.

## Claim boundary

The renderer serializes the report's existing run status, stop classification
code, resource accounting, and steps. For each outcome it emits only kind,
action identifier, severity, disposition, confidence, evidence count, and the
caller-supplied redacted summary. This is a privacy-minimized projection, not a
serialization of the complete `RunOutcomeRecord`. It does not serialize private
stop-reason/detail text. It also does not:

- accept legacy `ScanFinding` records;
- serialize outcome fingerprints, evidence identifiers, private subjects,
  rationales, cases, rules, hypotheses, or step details;
- compute a risk score or severity distribution;
- create a vulnerability or finding;
- reinterpret `Unknown` or `NeedsReview` as confirmation;
- imply that a bounded sample is complete; or
- alter the `decision-scan/v1` CLI wire contract.

If a selected representation cannot remain structurally valid within the hard
output ceiling, generation returns a typed error. It never reports a truncated
document as success. See [ADR 0021](adr/0021-render-bounded-run-reports.md) for
the durable boundary.
