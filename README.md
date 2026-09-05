# Termivar

[![CI](https://github.com/ITherso/termivar/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/ITherso/termivar/actions/workflows/tests.yml)
[![Docs](https://github.com/ITherso/termivar/actions/workflows/docs.yml/badge.svg?branch=main)](https://itherso.github.io/termivar/)
[![License](https://img.shields.io/github/license/ITherso/termivar)](LICENSE)

Termivar is a command-line tool for bounded web assessments. It records what
it observed, why an action ran, and what the evidence can support, then produces
readable HTML or structured JSON reports. Execution is deterministic and does
not require an LLM.

> Experimental and not production-ready; no independent security audit has been
> completed. Use only where you have explicit authorization. The published
> `v0.10.0-alpha.1` prerelease and unreleased `0.10.0-alpha.2` source are different
> builds. The walkthrough below uses only a credential-free local demonstration.

## Try it locally

1. [Download the exact v0.10.0-alpha.1 prerelease](https://github.com/ITherso/termivar/releases/tag/v0.10.0-alpha.1),
   then follow the [Linux, macOS, or Windows verification and extraction steps](docs/DISTRIBUTION.md#try-the-published-prerelease).
   No Rust toolchain is needed for the archived binary.
2. Alternatively, [build the reviewed development source](docs/DISTRIBUTION.md#build-from-source)
   at `57e5ddad7732b0b2c3d5988898aa2e4af5015195`.
3. [Run the local walkthrough](docs/GETTING_STARTED.md). It starts and stops its
   own tiny loopback fixture, runs the actual CLI, and saves separate default,
   JSON-assessment, and HTML-assessment outputs.

The walkthrough tools require Git and Python 3.12.4 or newer. They do not
download, build, install, or update a binary for you. The older release archives
do not include maintenance from PRs #109–#111 and are not recommended for
credentialed or production use.

[Read the version-labelled example reports](docs/examples/first-use/README.md):
[HTML](docs/examples/first-use/assessment.html) ·
[JSON](docs/examples/first-use/assessment.json) ·
[provenance](docs/examples/first-use/provenance.json).

Actual JSON fragment from the Windows x86_64 alpha.1 binary, captured in an
isolated directory on 2026-09-05:

```text
"title":"Permissions-Policy was not observed","disposition":"informational","claim_basis":"observation","severity":null
```

The completed sample has one subject and four informational observations. It
does not confirm vulnerabilities; the full reports and provenance are linked
above.

## What the output means

- A no-profile `scan` produces operational decisions and outcomes, not a
  findings report.
- Explicit `web-review` produces an assessment report when execution completes.
  `Informational` records an observation; `NeedsReview` asks for human review
  without confirming a vulnerability.
- `Success` means an action achieved its objective, not that it proved a
  vulnerability. An incomplete run is not a completed report with zero items.
- The absence of reported observations does not mean “secure,” “clean,” or
  “not vulnerable.”

See the [sample reading guide](docs/examples/first-use/README.md) and
[report contract](docs/reporting.md).

Saved complete assessment JSON files can also be compared without starting a
scan or making a network request:

```bash
termivar report compare \
  --before before.json \
  --after after.json \
  --same-scope
```

The explicit `--same-scope` flag records the operator's selection; Termivar
does not infer or authenticate target identity from a rendered report. The
comparison separates observations into only-in-after, only-in-before, changed,
and unchanged groups. Disappearance is not verified remediation. See the
[offline comparison contract and formats](docs/reporting.md#offline-assessment-report-comparison).

## What you can evaluate

- A bounded, exact-origin web assessment with evidence and completeness records.
- Human-readable HTML or Markdown and machine-readable JSON or CSV output,
  using the existing report renderer.
- Offline Markdown, JSON, or standalone HTML comparison of two supported,
  complete assessment JSON documents.
- Source-level Rust evidence, reasoning, and reporting contracts for an explicit
  library host; see the [architecture](docs/architecture.md).

The local fixture demonstrates command wiring and report usability—not
detection accuracy, exploitability, production readiness, or a complete security
assessment. It has no credentials, forms, query-driven endpoints, external
assets, or callbacks. Optional review flags are not enabled.

Termivar is not an unrestricted crawler, browser-based vulnerability verifier,
hosted scanning service, or production exploit framework. A compiled optional
feature is not runtime opt-in. The [feature lifecycle](FEATURES.md) and
[runtime map](docs/internals/runtime-map.md) describe the actual boundaries,
including the separately gated historical runner. F3 remains
[deferred, out of scope, and unresolved](docs/audits/native-oast-corrective-maintenance.md#finding-ledger).

## Documentation

| Read next | Details |
| --- | --- |
| [Getting started](docs/GETTING_STARTED.md) · [Distribution](docs/DISTRIBUTION.md) | One local walkthrough; release/source build choices |
| [Architecture](docs/architecture.md) · [Runtime map](docs/internals/runtime-map.md) · [Feature lifecycle](FEATURES.md) | Ownership, runtime limits, optional capabilities, and maturity |
| [Decision output](docs/internals/decision-scan-json-v1.md) · [Reporting](docs/reporting.md) | Operational output versus assessment reports |
| [Project status](PROJECT_STATUS.md) · [Quality metrics](docs/quality-metrics.md) · [Repository health](docs/repository-health.md) | Open release gates and the limits of CI evidence |
| [Scanner SDK](docs/sdk.md) · [Plugins](docs/plugin.md) · [Compatibility](docs/public-api-compatibility.md) | Legacy SDK and Preview library contracts, not a stable ABI promise |
| [Historical scanner salvage](docs/history/historical-scanner-salvage.md) · [WAF/evasion salvage](docs/history/post-workspace-waf-evasion-salvage.md) | Preserved source history, not executable authority |
| [Credential-input limits](docs/internals/credential-input.md) · [Corrective maintenance](docs/audits/native-oast-corrective-maintenance.md) | Precise current-source guarantees and unresolved work |
| [Documentation site](https://itherso.github.io/termivar/) · [Rust API](https://itherso.github.io/termivar/rust/termivar_scanner/) | Full reference documentation |

Termivar was formerly developed under the name Venom. Historical schema,
digest, compatibility, and provenance identifiers remain where changing them
would break identity or historical integrity; see the
[migration guide](docs/migrations/venom-to-termivar.md).

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) and the
[Code of Conduct](CODE_OF_CONDUCT.md). Report security issues privately according
to [SECURITY.md](SECURITY.md). Roadmap items and alpha APIs are not delivery or
compatibility guarantees.

## License

[MIT](LICENSE).
