# Bounded report rendering

The opt-in `reporting` feature is a Preview source-level contract with two
related inputs. It retains the standalone renderer for a host-owned typed
`RunReport`, and—when `scanning` is also enabled—adds the central typed
assessment composition and rendering path used by completed CLI `web-review`
runs. Neither path is a scanner, persistence layer, or independent verdict
authority.

## Runtime scope

| Surface | Input | Schema | Caller and redaction boundary |
| --- | --- | --- | --- |
| Generic run report | Immutable, constructor-validated `RunReport` | `venom-rendered-run/v1` | Standalone library hosts call `ReportGenerator::generate`; they must pre-redact every projected free-text field |
| Typed assessment report | Completed runtime-owned `WebAssessmentRunReport` plus the exact validated `ScanProfileV1`, composed into `AssessmentRunReport` | `venom-rendered-assessment/v1` | `scanning + reporting` library hosts and the CLI call the central composition/renderer; assessment summaries and references are already redacted before rendering |

Both paths return `Result<String, ReportError>`, support the same
`ReportFormat` values, and enforce `MAX_RENDERED_REPORT_BYTES` (16 MiB). A
rendering failure returns no partial document. Rendering itself performs no
filesystem or network I/O and does not persist output.

The no-profile CLI path never calls the assessment composer and its
[`decision-scan/v1`](internals/decision-scan-json-v1.md) contract remains
unchanged. The explicit `baseline` profile likewise does not use the typed
assessment renderer.

## Standalone generic API

Enable only `reporting` for a host that already owns a `RunReport`:

```toml
[dependencies]
termivar-scanner = { path = "/path/to/reviewed/termivar/crates/termivar-scanner", default-features = false, features = ["reporting"] }
```

```rust,ignore
use termivar_scanner::{ReportFormat, ReportGenerator, RunReport};

fn render(report: &RunReport) -> Result<String, termivar_scanner::ReportError> {
    ReportGenerator::generate(report, ReportFormat::Json)
}
```

The same input and format produce the same document. Format encoding is not
redaction: this generic path copies `target`, `authorized_origin`, step/outcome
`action_id`, and outcome `redacted_summary`. The library host must pre-redact
those fields and decides whether and where to persist the returned string.

## Typed assessment API

With both `scanning` and `reporting`, a host can compose only completed,
runtime-owned assessment truth:

```toml
[dependencies]
termivar-scanner = { path = "/path/to/reviewed/termivar/crates/termivar-scanner", default-features = false, features = ["scanning", "reporting"] }
```

```rust,ignore
use termivar_scanner::{ReportFormat, ReportGenerator};
use termivar_scanner::web_runtime::{ScanProfileV1, WebAssessmentRunReport};

fn render_assessment(
    runtime_report: WebAssessmentRunReport,
    profile: ScanProfileV1,
) -> Result<String, Box<dyn std::error::Error>> {
    let report = ReportGenerator::compose_assessment(runtime_report, profile)?;
    Ok(ReportGenerator::generate_assessment(
        &report,
        ReportFormat::Json,
    )?)
}
```

Composition validates that the assessment completed, that its limits and
defense mode match the selected `web-review` profile, and that accounting and
opaque item references belong to the same runtime truth. The generic run
envelope is minted internally from runtime-owned clock and accounting data;
the caller cannot substitute a generic `RunReport` as assessment authority.

The typed renderer keeps `Informational`, `NeedsReview`, and `Confirmed`
visibly distinct in every format. It preserves each item's claim basis and,
when present, its complete opaque verifier/case/outcome linkage. Incomplete or
cross-context linkage fails closed. It does not promote an item, infer a claim
from action success, synthesize CVSS/risk, or accept legacy `ScanFinding`
records. The currently implemented native passive header/cookie capabilities
emit only `Informational`; no native assessment capability currently produces
`Confirmed`.

The exact origin root retains `authorized-root@1`. Eligible discovered
exact-origin subjects can enter this completed-report path through opaque,
deterministic `discovered-resource@1` identities; renderers receive only the
existing references and digests, never query values or readable path material.
A non-root starting target remains typed incompleteness.

## CLI assessment output

Completed `--profile web-review` runs always use the typed assessment renderer:

```bash
# Default text selection maps to Markdown.
termivar scan <AUTHORIZED_TARGET> --profile web-review

# Existing --format json maps to the additive assessment JSON schema only
# because web-review was explicitly selected.
termivar scan <AUTHORIZED_TARGET> --profile web-review --format json

# Select any central renderer explicitly.
termivar scan <AUTHORIZED_TARGET> --profile web-review --report-format csv
termivar scan <AUTHORIZED_TARGET> --profile web-review \
  --report-format html --report-output assessment.html
```

`--report-format` accepts `json`, `csv`, `html`, or `markdown` and requires
`--profile web-review`. `--report-output` additionally requires an explicit
`--report-format`. A completed file-output run writes no report document to
stdout.

The CLI creates a same-directory temporary file with exclusive creation,
writes and synchronizes the complete rendered bytes, then publishes the new
destination with a hard link. It never overwrites an existing destination and
attempts best-effort temporary-file cleanup on failure. If cleanup after the
hard link fails, the complete destination and temporary file can both remain
while the command returns nonzero; it does not report publication success.
Directory-metadata crash durability is best effort, and filesystems without the
required same-directory hard-link semantics fail nonzero.

## Offline assessment report comparison

`termivar report compare` reads exactly two explicit local files and performs
no scan, target request, credential lookup, provider operation, or browser
launch. It accepts supported, complete `venom-rendered-assessment/v1` JSON
documents, including renderer output with the current optional audit sections.
It rejects operational `decision-scan/v1` output, incomplete diagnostic
envelopes, unknown schemas, duplicate JSON keys or item identities, malformed
fingerprints, inconsistent counts, and inputs above the 16 MiB per-file limit.

```bash
# Markdown to stdout (the default).
termivar report compare \
  --before before.json \
  --after after.json \
  --same-scope

# Structured comparison to a new file.
termivar report compare \
  --before before.json \
  --after after.json \
  --same-scope \
  --format json \
  --output changes.json

# Standalone interactive comparison to a new file.
termivar report compare \
  --before before.json \
  --after after.json \
  --same-scope \
  --format html \
  --output changes.html
```

`--same-scope` is required. It records only the operator's assertion that the
two files were deliberately selected for comparable assessment scope; parsing
does not authenticate either source or reconstruct target identity. Source
hashes are included, but a hash provides integrity identification rather than
authenticity. The documents may differ in enabled work or retained evidence,
so equivalent assessment coverage is not established.

Items match by the renderer's existing stable fingerprint together with the
compatible capability identity. Array/key order and report-local subject,
evidence, case, and outcome reference numbering do not define identity. The
new `termivar-report-comparison/v1` projection has four mutually exclusive
groups:

- `only_in_after`: present only in the supplied after document;
- `only_in_before`: present only in the supplied before document;
- `changed`: matched identity with different supported comparable content;
- `unchanged`: matched identity with equal supported comparable content.

Only-in-before does not mean fixed, resolved, verified-remediated, or safe.
Only-in-after does not establish when an observation first appeared. Unchanged
means only that the supported display projection is equal; it is not proof of
security or equal scan coverage. Imported disposition, claim basis, severity,
CWE, confidence, summary, remediation, and selected evidence-linkage metadata
are displayed without independent endorsement. No CVSS, evidence, verdict, or
target identity is reconstructed.

Without `--output`, the complete selected encoding goes to stdout and
diagnostics go to stderr. With `--output`, the existing same-directory atomic,
no-overwrite publisher is used: an existing destination or an input/output
collision fails, and malformed input produces no partial destination. Inputs
are opened as bounded regular files and never modified. Exit `0` means the
offline comparison document was produced; invalid CLI usage exits `2`; input,
comparison, or publication failures exit nonzero (normally `1`). Error text
does not echo supplied paths or document bodies.

Markdown is the terminal default. JSON is deterministic structured output.
The standalone HTML includes four count cards, group filters, text search,
expandable before/after fields, responsive dark/light styling, keyboard focus,
and print styling. It has no external resources, storage, forms, frames, or
network capability. Imported values are pre-rendered as encoded text. A small
fixed CSP-hashed script changes only `textContent`, `hidden`, expanded details,
and filter-button state; with scripts blocked, all comparison entries remain in
the document and can be read or expanded. Encoding prevents active markup; it
does not remove secrets from untrusted imported text, so review output before
sharing it.

A small [synthetic CLI-generated example](examples/report-compare/README.md)
demonstrates all four groups. Its edited input is document-processing fixture
data, not another assessment and not evidence that a security condition changed.

An incomplete or started-failed `web-review` assessment is not a partial typed
report. It emits the redacted `web-assessment/v2` diagnostic audit to stdout,
marks assessment items unavailable, returns nonzero, and creates no requested
report artifact. A failure before runtime execution starts also returns nonzero
without creating an artifact.

## Formats and bounds

Format negotiation is available through
`ReportGenerator::available_formats()`:

| Variant | Token | Media type | Extension |
| --- | --- | --- | --- |
| `Json` | `json` | `application/json` | `json` |
| `Csv` | `csv` | `text/csv; charset=utf-8` | `csv` |
| `Html` | `html` | `text/html; charset=utf-8` | `html` |
| `Markdown` | `markdown` | `text/markdown; charset=utf-8` | `md` |

`ReportFormat::as_str`, `media_type`, and `extension` expose those values. A
render can fail with `ReportError::Serialization` or
`ReportError::OutputLimitExceeded`; neither error returns a truncated document.

JSON preserves full-width integer fields as decimal strings where the v1
schema requires portability and escapes controls and bidirectional controls.
CSV quotes every cell, neutralizes spreadsheet-formula prefixes, and uses
visible reversible escapes. HTML and Markdown apply context-specific encoding
to every projected text value.

See [ADR 0021](adr/0021-render-bounded-run-reports.md) for the original generic
renderer boundary and [ADR 0023](adr/0023-compose-profiled-assessment-reporting.md)
for the additive CLI composition and publication boundary. The typed assessment
schema does not reinterpret the generic renderer contract or `decision-scan/v1`.
