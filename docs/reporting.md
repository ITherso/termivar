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

```rust
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

```rust
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
A non-root starting target remains typed incompleteness unless the explicitly
selected WordPress metadata-discovery path binds it to a validated application
reference. The projected item keeps the stable origin-root subject; deployment
scope is carried by the versioned WordPress discovery audit.

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

### Optional live progress channel

The unreleased `0.10.0-alpha.3` development source accepts `--progress` only
with an explicit `--profile web-review`. Published `v0.10.0-alpha.2` archives
do not contain the flag. It is a bounded, lossy stderr presentation channel;
it does not alter assessment execution, deadlines, request ceilings, report
selection, or any report schema.

```bash
termivar scan <AUTHORIZED_TARGET> \
  --profile web-review \
  --progress \
  --report-format html \
  --report-output assessment.html 2> progress.log
```

Every emitted line is fixed-shape ASCII beginning with `[progress]`. Lifecycle
states separate assessment execution, composition, rendering, stdout writing,
file or bundle publication, and terminal completion/failure. Periodic running
snapshots are sampled once per second and may be coalesced or dropped when the
stderr sink is slow. A blocked stderr sink cannot exert assessment
backpressure; at most one detached presentation writer may remain until process
exit. If that OS write retains the shared process stderr lock, later diagnostics
can also wait behind it; the 250 ms worker handoff is not a universal bounded
process-exit guarantee. Progress I/O failure disables the channel without
changing the scan result.

All numeric fields use `counts=last_observed`. Accounted requests and active
verifications are cumulative parent-budget charges, not completed responses or
current concurrency. `subjects_started` marks child-runtime execution and
`subjects_processed` marks state committed for report projection; neither is a
success or finding count. Counts not yet supplied by a runtime checkpoint are
rendered as `unknown`, not inferred zeroes. The stream provides no percentage,
ETA, target/path, finding, severity, or vulnerability verdict. It remains
outside stdout, rendered documents, bundle payloads, and manifests, preserving
machine-readable output purity. A successful terminal state follows successful
selected-output publication; a bundle publication failure can report only its
typed manifest commit state.

The monotonic `elapsed_ms` presentation clock starts after runtime construction,
immediately before the one assessment analysis. Its terminal observation is
taken after the selected stdout or file publication succeeds or fails, so it
includes composition, rendering, publication, and progress handoff time. It is
separate from and does not replace, pause, extend, or alter the assessment
deadline clock.

## Single-run report bundles

The published `v0.10.0-alpha.2` binary and later development source can render
both assessment formats from one completed run:

```bash
termivar scan <AUTHORIZED_TARGET> \
  --profile web-review \
  --report-dir ./assessment-001
```

`--report-dir` requires an explicit `--profile web-review` and conflicts with
both `--report-format` and `--report-output`. It does not change feature
defaults. The existing `--format text|json` selection remains independent: it
controls the diagnostic envelope if a started assessment is incomplete or
fails, not the two formats in a successful bundle. A successful bundle writes
no report document to stdout.

The assessment executes once and is composed once into the existing immutable
typed assessment model. The existing renderer then produces HTML and JSON from
that same value; output selection does not replay target requests. A successful
destination contains exactly:

```text
assessment-001/
  assessment.html
  assessment.json
  manifest.json
```

The HTML remains the existing self-contained, script-free assessment document.
The JSON retains `venom-rendered-assessment/v1` and can be supplied directly to
`termivar report compare`. Each report keeps the existing 16 MiB document
ceiling. The manifest is bounded to 64 KiB and uses the additive
`termivar-report-bundle/v1` schema. It records the Termivar package version,
completed profile/status and available typed counts, plus exactly two sorted
payload entries with fixed relative names, media types, exact byte lengths, and
lowercase SHA-256 digests. It neither hashes itself nor includes a target URL,
credential, local absolute path, response body, or invented source/run identity.
Checked arithmetic also caps the total in-memory bundle payload at two report
ceilings plus the manifest ceiling (32 MiB + 64 KiB).

The destination must not already exist. Its parent must already exist as a
trusted, private, user-owned directory; Termivar does not create missing
ancestors. Files, directories, links, `.`, `..`, roots, and invalid final
components are rejected as destinations. Exclusive creation of the final
directory reserves it before credential loading or network construction, so a
competing writer cannot reuse an existing directory. Newly owned outputs use
restrictive permissions where the platform supports them. On Windows, the new
directory inherits its parent's ACL; Termivar does not claim to install a new
ACL policy. Trust in the parent path remains an explicit boundary.
Termivar verifies that the immediate parent is an existing non-link directory;
the operator's ownership/private-directory assertion is a precondition, not a
whole-path ownership or ancestor-integrity check performed by this command.
That trust boundary also assumes another actor able to mutate the parent does
not race file replacement against publication or cleanup.

Publication renders and bounds all documents before committing final report
names. It publishes and synchronizes `assessment.html` and `assessment.json`,
then publishes `manifest.json` last with no-overwrite file semantics. The final
manifest is the bundle's completion marker: readers must verify its two names,
lengths, and hashes before treating the directory as complete. Payload files
and temporary construction state can be visible before that point, so the
three-file operation is not an atomic directory snapshot for arbitrary readers.
The digests identify exact bytes; they are not signatures and do not establish
source authenticity, trusted scope, remote delivery, or remediation.

Before the manifest commit point, ordinary failures attempt to remove only
known files owned by that publication and then only an empty owned directory.
Cleanup uncertainty is reported instead of deleting unknown contents. If the
manifest was committed but temporary-file housekeeping later fails, the valid
committed files are retained and the command reports the post-commit error; it
does not claim rollback. A crash or forced termination can leave an incomplete
directory, and that directory must be inspected or removed deliberately rather
than reused for another bundle. File synchronization and best-effort supported
directory synchronization do not promise universal power-loss durability.

To compare JSON from two deliberately selected bundles without starting a new
scan:

```bash
termivar report compare \
  --before assessment-001/assessment.json \
  --after assessment-002/assessment.json \
  --same-scope
```

The preserved `v0.10.0-alpha.1` archives predate `--report-dir`; their genuine
first-use JSON and HTML captures remain separate assessment executions. The
published alpha.2 archives include the bundle command.
The [development report-bundle example](examples/report-bundle/README.md)
records one local loopback run, exact payload hashes, and an offline
self-comparison without relabelling it as release or effectiveness evidence.

## Offline report-bundle verification

The published `v0.10.0-alpha.2` binary and later development source can check a
saved bundle with Report Bundle Verification V1 without starting a scan:

```bash
# Human-readable result (the default).
termivar report verify --dir ./assessment-001

# One bounded structured result on stdout.
termivar report verify --dir ./assessment-001 --format json
```

The verifier accepts one explicit directory and the strict
`termivar-report-bundle/v1` layout only:

```text
assessment-001/
  assessment.html
  assessment.json
  manifest.json
```

It rejects missing or additional entries and does not recurse. Manifest names
are validated against the two fixed payload names rather than treated as paths.
The command reads the manifest within its 64 KiB limit and each payload within
the existing 16 MiB report limit. It checks the fixed formats and media types,
measures and hashes the exact bytes captured from each opened payload, validates
`assessment.json` through the existing display-only assessment importer, and
compares its completed profile, subject count, and item count with the manifest.
HTML is checked only for bounded UTF-8 bytes, length, and digest; it is never
launched, rendered, or executed.

The result schema is `termivar-report-verification/v1`. Its checks distinguish
`checked_matched`, `checked_mismatched`, and `not_checked`; a failure that stops
the pipeline cannot make a dependent check look successful. `integrity_match`
means only that the supported layout, manifest contract, captured payload bytes,
and assessment JSON summary matched during that invocation. `not_verified`
uses bounded reason codes such as `missing_manifest`,
`payload_digest_mismatch`, or `assessment_summary_mismatch` without echoing
document contents or absolute paths.

Exit `0` means every supported check completed and matched. Exit `1` means the
bundle was incomplete, unreadable, unsupported, mismatched, or otherwise could
not be verified. Invalid command syntax exits `2` through Clap. After valid
argument parsing, both an integrity match and an ordinary verification failure
produce exactly one text or JSON result on stdout. An output-write failure is a
separate nonzero error because the CLI cannot guarantee that the result reached
the caller completely.

Verification is read-only application behavior: it initializes no scanner,
network client, credential source, or provider, and it does not write, repair,
remove, rename, or change permissions inside the bundle. Filesystem access-time
metadata remains outside that application-level promise. A caller-selected
mounted filesystem may still be remotely backed; "offline" means the command
itself issues no network requests. The bundle must be quiescent beneath trusted
parent directories. The command rejects a
symlink/reparse-point final directory and non-regular payloads, retaining and
validating opened handles; this does not establish whole-path containment when
an untrusted actor can replace parent components, or establish provenance for a
regular hard link. Hashing and assessment parsing use the same captured payload
bytes, but verification is not an atomic snapshot and cannot guarantee that the
directory remains unchanged afterward or detect every concurrent same-size
in-place write.

Matching hashes are integrity metadata, not a signature. Verification does not
establish producer/source authenticity, the validity or authorization scope of
the original scan, finding accuracy, remediation, HTML-to-JSON semantic
equivalence, or executable HTML safety. An editor can modify a payload and its
manifest consistently and still receive `integrity_match`; authenticity remains
`not_established`.

After verification, the same validated bundle JSON can be used by the existing
offline comparison command without conversion:

```bash
termivar report compare \
  --before assessment-001/assessment.json \
  --after assessment-002/assessment.json \
  --same-scope
```

Both report commands are offline document operations, but they answer different
questions: verification checks one bundle's supported internal consistency;
comparison groups imported observations from two operator-selected reports.
Neither certifies security or remediation. The published alpha.2 archives
contain `report verify`; the preserved alpha.1 archives do not.

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

When at least one imported assessment contains a supported WordPress audit,
the comparison includes the additive optional
`wordpress_review_comparison` section. Its nested schema is
`termivar-wordpress-review-comparison/v1`; the outer comparison remains
`termivar-report-comparison/v1`, and the four item groups above retain their
existing identities and meanings. If neither input has a WordPress audit, the
section is omitted.

WordPress correlation is valid only inside the same operator-declared
`--same-scope` boundary. Components use component kind plus canonical slug as
their stable key. Native advisory keys add `catalog.id` and the upstream
advisory ID; external keys instead add the source namespace and upstream ID.
External audit `/v6` keys use the retained raw source kind and source identifier,
so case-only source spelling and otherwise non-canonical provider identities are
not silently collapsed. Structurally valid source associations that cannot be
represented as canonical Termivar components remain accounted for in the
unresolved total. Up to the bounded deterministic projection is emitted as
explicit `canonical_identity_unavailable` / `not_evaluated` advisory
limitations; those projected rows keep their affected ranges, source-declared
patch/remediation fields, bibliography, and bound notices visible and
comparable. The remaining unprojected rows are represented only by reconciled
coverage counts, without inventing an installed component or applicability
result.
Array position, display title, CVE, and report-local ordering are not identity.
The comparison keeps component evidence, advisory content, affected ranges,
source-declared fix/remediation information, methodology, provenance, coverage,
and applicability changes separate rather than attributing one to another.

If exactly one input has a WordPress audit, the WordPress result is
`not_compared` with `coverage_changed`; records on the present side are not
classified as newly vulnerable or remediated. More generally, an advisory's
disappearance or an applicability transition is document change, not proof of
a fix, a new vulnerability, or a change at the installation.

The importer supports the historical
`security.wordpress-review-audit/v1` through `/v4` contracts and the additive
`/v5` and `/v6` contracts. `/v6` carries the explicit raw-source identity
mapping and bounded-capacity policy (including the additive 160 MiB V3 import
envelope while preserving the older V1/V2 ceilings), accounted retained-import
bytes, reconciled
mapped/unresolved association partitions, and the non-canonical identity
limitations described above. The complete unresolved total is retained while
at most 64 deterministically ordered limitation rows are expanded; the explicit
projected/unprojected counts prevent that bounded report view from looking like
complete per-record detail. Historical `/v4` and `/v5` external rows are
normalized as canonical exact mappings for semantic comparison, so a
capacity-only `/v5` to `/v6` transition does not falsely report every exact
advisory identity as changed. The `/v5` contract is produced when an operator explicitly selects a Termivar
interpretation profile for local Wordfence ranges. The `/v5` comparison keeps
the selected profile, explicit-operator basis, and unestablished source-semantics
assurance in the methodology facet. A transition from an unresolved `/v4`
result to a calculated `/v5` result, or between `/v5` profiles, is therefore a
methodology change—not evidence that an installation or vulnerability changed.
For wire compatibility, the v5 `unsupported_associations` count is the same
partition as `indeterminate_associations`; human output shows the precise
indeterminate label once rather than describing missing, conflicting, or invalid
cases as unsupported.
Each version is compared only to the depth of typed meaning it actually carries.
Exact-input byte digests identify provenance bytes, not semantic identity or
source truth: bytes can differ while the supported semantic projection remains
equal. This comparison only reads the two saved reports; it does not rerun the
scanner, WP-CLI, PHP, an advisory lookup, or any network operation.

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
