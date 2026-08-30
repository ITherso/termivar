# ADR 0023: Compose profiled assessment reporting at the CLI boundary

- Status: Accepted
- Date: 2026-08-30

This decision supersedes only the current-runtime statements in
[ADR 0021](0021-render-bounded-run-reports.md) that no repository CLI, default
scan path, or distribution artifact calls the renderer; that hosts always
select a format explicitly; and that adding a repository caller requires a
later composition decision. The supersession is limited to the explicit
profiled CLI path: the no-profile default remains unchanged, while the CLI may
select Markdown or JSON through its existing output policy. ADR 0021's renderer
authority, encoding, redaction, determinism, ambient-authority prohibition, and
output-size decisions remain in force.

## Context

The deterministic scanner now has an additive, explicit `web-review` profile
that can project completed exact-origin runtime truth into typed
`AssessmentItem` records and render those records as JSON, CSV, HTML, or
Markdown. This composition must not replace the existing conservative command
or reinterpret action outcomes as vulnerability claims. It also needs a clear
authority split between runtime projection, format rendering, and filesystem
publication so an incomplete execution or write cannot appear successful.

The profile and assessment APIs remain alpha/Preview surfaces. Their existence
does not establish a stable Scanner SDK or plugin v1 baseline, an independent
security audit, external adoption, or a performance service-level agreement.

## Decision

- With no explicit `--profile`, `venom scan <TARGET>` keeps the conservative
  single-resource runtime and the existing `decision-scan/v1` JSON contract.
  The `decision-scan` spelling remains an alias of that same command. The
  additive assessment path cannot silently change this compatibility surface.
- Profile selection is explicit and fail-closed. The CLI accepts only the exact
  built-in `baseline` and `web-review` identifiers, constructs the strict
  `venom.scan-profile/v1` contract, rejects incompatible flags before runtime
  dispatch, and does not infer an origin crawl from the absence of a profile.
- A completed `web-review` run may be composed into an `AssessmentRunReport`.
  Assessment claim authority remains in the runtime-owned typed projection:
  an observation maps to `Informational`, a matched differential maps to
  `NeedsReview`, and `Confirmed` requires the separately authorized,
  case-correlated verifier transition defined by the claim policy. These
  dispositions remain distinct in JSON, CSV, HTML, and Markdown. Action success
  alone, including a `KnowledgeOnly` success, cannot authorize confirmation.
- `ReportGenerator` owns deterministic, context-appropriate encoding and the
  16 MiB rendered-output ceiling. It receives an already validated typed report
  and cannot classify severity, promote a disposition, create a verifier
  transition, choose a path, or publish to the filesystem. Exceeding the bound
  or failing serialization returns no partial successful document.
- Report publication is a CLI boundary and is opt-in. `--report-format` is
  available only with `--profile web-review`; `--report-output` additionally
  selects explicit file publication. Without `--report-output`, a completed
  report is written to standard output. No scan creates a report file by
  default.
- For file output, the CLI renders the complete bounded artifact in memory,
  writes and synchronizes a same-directory temporary file, then publishes it
  without overwriting an existing destination. The current implementation uses
  a same-directory hard link and therefore requires filesystem support for that
  operation; it does not promise crash-durable directory metadata. A rendering,
  temporary-write, synchronization, link, cleanup, incomplete-execution, or
  started-execution failure is not reported as file-output success. If the hard
  link succeeds but removal of the temporary name fails, the complete
  destination and temporary link may both remain while the command returns
  nonzero; a retry still cannot clobber the destination. Incomplete and failed
  assessment diagnostics do not create the requested destination; they remain
  visibly separate from a completed assessment report, are emitted to standard
  output, and return nonzero after execution has started.
- The CLI reads any authorization context only from the explicit bounded secret
  sources supported by the `web-review` path. Raw credentials are not fields in
  profile, assessment, or rendered-report contracts.

## Consequences

- `decision-scan/v1` consumers are unaffected unless a caller explicitly opts
  into a product profile; additive profile and assessment schemas can evolve
  under their own versioning rules.
- Runtime projection, rendering, and publication have separate authorities and
  failure boundaries. Renderer success does not imply filesystem success, and
  transport/action success does not imply a confirmed security claim.
- The CLI can provide all four existing safe encodings without introducing a
  second renderer or stringly finding model.
- File publication is intentionally conservative: it never clobbers an existing
  path and can fail on filesystems without the required same-directory hard-link
  semantics.
- This decision records executable alpha/Preview behavior only. It does not
  declare a stable v1 SDK/plugin compatibility baseline, audit completion,
  downstream adoption, benchmark regression threshold, or performance SLA.

## Alternatives considered

- **Replace `decision-scan/v1` with the assessment document.** Rejected because
  an opt-in product capability cannot silently alter the established machine
  contract or default network scope.
- **Let the renderer derive dispositions from outcomes.** Rejected because
  encoding has no verifier or claim-policy authority; action success and
  evidence observation are not vulnerability confirmation.
- **Write files from `ReportGenerator`.** Rejected because path selection,
  overwrite policy, atomic publication, and I/O failure handling belong to the
  host/CLI boundary rather than the pure renderer.
- **Publish partial or truncated output with a warning.** Rejected because a
  syntactically valid fragment could omit execution or claim context and appear
  to be a completed report.
- **Enable `web-review` discovery by default.** Rejected because origin-wide
  discovery is a deliberate authority expansion from the conservative
  single-resource compatibility behavior.
