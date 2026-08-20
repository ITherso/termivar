# ADR 0021: Render bounded typed run reports

- Status: Accepted
- Date: 2026-08-20

This decision supersedes the reporting-specific compatibility decision in
[ADR 0020](0020-quarantine-platform-and-distribution-surfaces.md). The broader
platform and distribution quarantine remains in force.

## Context

The opt-in reporting module accepted raw `ScanFinding` records and created a
second report model. It assigned aggregate severity counts and a synthetic risk
score from caller-controlled strings, captured wall-clock time, interpolated
unescaped values into output, and returned an unbounded `String`. That contract
could turn compatibility observations into a stronger-looking vulnerability
verdict even though it had no verifier authority. It also forced the reporting
feature to enable `venom-core/legacy-contracts`.

The deterministic and legacy runtimes already converge on the typed,
constructor-validated `RunReport` boundary. A report renderer should preserve
that boundary instead of inventing another finding model or execution path.

## Decision

- The opt-in `reporting` feature depends on exactly `core`; it does not enable
  `venom-core/legacy-contracts` and cannot import `ScanFinding`.
- `ReportGenerator::generate` accepts an immutable `RunReport` and a
  `ReportFormat`, and returns `Result<String, ReportError>`.
- The renderer preserves the input report's typed status, stop classification
  code, accounting, and steps, then emits a privacy-minimized outcome
  projection containing kind, action identifier, severity, disposition,
  confidence, evidence count, and the caller-supplied redacted summary. It does
  not serialize private stop reason/detail text, calculate risk, classify
  severity, create findings, or promote an observation into a verdict.
- Every format identifies its `venom-rendered-run/v1` document contract with
  `REPORT_DOCUMENT_SCHEMA`. Every rendered document is limited by the 16 MiB
  `MAX_RENDERED_REPORT_BYTES` ceiling; a document that cannot fit fails closed
  with a typed error instead of returning a truncated or oversized success.
- Text inserted into a structured format is encoded for that format. Encoding
  is not redaction: the renderer copies the report's `target`,
  `authorized_origin`, step/outcome `action_id`, and outcome
  `redacted_summary` fields, so callers must redact those values before
  constructing or passing the report. Rendering is deterministic for the same
  `RunReport` and format and does not read the clock, filesystem, network,
  process environment, randomness, or mutable scanner state.
- The module is a source-level Preview host-library API. No repository CLI,
  default scan path, persistence layer, or distribution artifact calls it.
  Hosts explicitly choose a format and own any storage or delivery after a
  successful render.
- Static architecture checks pin the feature closure, constants, exact public
  items and signatures, public-type trait implementations, public attributes,
  re-exports, lifecycle/host classification, retired API absence, output-order
  determinism, statelessness, and ambient-authority-free source boundary.

## Consequences

- `VulnerabilityReport`, `severity_stats`, `phase_stats`, and `risk_score` are
  removed. The reporting API changes intentionally on the unreleased alpha
  line.
- The renderer can present only claims already encoded by `RunReport`. It is
  not a vulnerability report, security verdict, audit result, or persistence
  mechanism.
- The projection intentionally omits outcome fingerprints and private evidence
  identifiers, subjects, rationales, cases, rules, hypotheses, step details,
  and stop detail; these are not renderer output fields.
- The default `venom scan` command and its historical `decision-scan/v1` JSON
  wire remain unchanged. Adding a repository caller requires a separate
  composition decision and compatibility review.
- Bounded input records plus an independent output ceiling make memory growth
  reviewable, but they do not make an external host's storage or delivery
  bounded.

## Alternatives considered

- **Harden the raw-finding renderer in place.** Rejected because escaping and
  output limits would not repair its authority problem or duplicated report
  model.
- **Make rendering part of the default CLI.** Rejected because the CLI already
  has a versioned output contract; silently replacing or wrapping it would be a
  product and wire change.
- **Write files from the reporting module.** Rejected because format conversion
  and persistence have different authority, failure, and path-safety concerns.
- **Truncate oversized documents.** Rejected because truncation could silently
  remove stop, accounting, or outcome context and make a partial report appear
  complete.
