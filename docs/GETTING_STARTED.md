# Getting started

This walkthrough runs the actual CLI against a tiny, repository-owned static
demonstration. It is credential-free and uses only numeric loopback
`127.0.0.1`. It demonstrates command behavior and report reading, not detection
accuracy or the security of an application.

Choose one binary first:

- [Published prerelease: v0.10.0-alpha.2](DISTRIBUTION.md#try-the-published-prerelease):
  manually download, verify, inspect, and extract your platform archive. No
  Rust toolchain is required.
- [Preserved pinned source example: 0.10.0-alpha.2](DISTRIBUTION.md#build-from-source):
  build package `termivar-cli` from the reviewed full commit
  `a29ba40c8cfdc7d0385431ea4d9e374e213ca4e0` in a separate source tree.

The historical alpha.1 archives do not include maintenance from PRs #109–#111.
Alpha.2 includes those changes, but neither release is independently audited or
production-ready. The
[distribution comparison](DISTRIBUTION.md) records the exact release identity
and build features.

## Prerequisites

Use Python **3.12.4 or newer** and a reviewed Git checkout containing this
guide and `scripts/first_use.py`. Run the examples from that **tools checkout**,
not from the separate pinned source tree. Git is needed to obtain the scripts;
they are not included in the binary archive. Record the tools checkout revision
with `git rev-parse HEAD` and inspect the script before running it.

The runner takes an already acquired local executable. It never downloads,
installs, compiles, or updates tools. Its output directory must not exist, and
its parent must already exist in a trusted, private user-owned location.
No administrator privileges or global PATH change is needed.

Once the binary and tools are acquired, exercise traffic stays on loopback.
If HTTP, HTTPS, or all-proxy environment configuration is present, the runner
refuses to begin instead of changing proxy policy. Host security controls stay
enabled; a blocked executable is an unexecuted step, not a reason to bypass
App Control, antivirus, or Gatekeeper.

## Run the local walkthrough

For the verified, locally extracted **published prerelease**:

Linux/macOS:

```bash
python3 scripts/first_use.py \
  --binary ./termivar-alpha2/termivar \
  --output first-use-release-output \
  --source-ref v0.10.0-alpha.2 \
  --build-features release-bundle \
  --expect-version 0.10.0-alpha.2
```

Windows PowerShell:

```powershell
python scripts/first_use.py --binary .\termivar-alpha2\termivar.exe --output first-use-release-output --source-ref v0.10.0-alpha.2 --build-features release-bundle --expect-version 0.10.0-alpha.2
if ($LASTEXITCODE -ne 0) { throw "First-use acceptance did not pass; inspect its diagnostics" }
```

The runner first captures `--version`, `--help`, and `scan --help`. It then
binds its own allocated loopback port before checking readiness. There is no
target-URL option. The fixture serves only fixed `/` and `/example` documents
with simple GET/HEAD behavior and a fixed response for unknown paths. It never
serves your checkout, home directory, or other files.

There are no forms, query-driven endpoints, credentials, callbacks, external
links/assets, or external fetches. The runner starts and stops only its own
fixture and CLI child. Success, error, and cancellation paths request cleanup;
any recorded cleanup failure is a failure to investigate, not a passed run.
It never kills an unrelated process or reclaims an occupied port.

### Development source binary

After the [separate pinned source build](DISTRIBUTION.md#build-from-source),
run from the tools checkout with the default source binary:

Linux/macOS:

```bash
python3 scripts/first_use.py \
  --binary ../termivar-source-a29ba40/target/release/termivar \
  --output first-use-source-output \
  --source-ref a29ba40c8cfdc7d0385431ea4d9e374e213ca4e0 \
  --build-features default \
  --expect-version 0.10.0-alpha.2
```

Windows PowerShell:

```powershell
python scripts/first_use.py --binary ..\termivar-source-a29ba40\target\release\termivar.exe --output first-use-source-output --source-ref a29ba40c8cfdc7d0385431ea4d9e374e213ca4e0 --build-features default --expect-version 0.10.0-alpha.2
if ($LASTEXITCODE -ne 0) { throw "First-use acceptance did not pass; inspect its diagnostics" }
```

The default CLI feature list is empty; its scanner dependency enables
`scanning` and `reporting`. If you deliberately built the same source with
`release-bundle`, use that separate executable path, declare
`--build-features release-bundle`, and choose another fresh output directory.
Compiling optional capabilities does not enable their runtime actions.
No optional review flags are used here.

The runner measures the executable hash and checks the actual version. The
source ref and feature set are **caller declarations**, not inferred or attested
by `--version`. Record the real revision and build command; never relabel a
source build as release-archive acceptance.

## Inspect compiled CLI capabilities

A development binary whose top-level help lists `capabilities` can describe
its own fixed CLI surface without a target, credentials, repository, Cargo,
Git, Python, or scanner startup:

```bash
termivar capabilities
termivar capabilities --format json
```

The synchronous command reports the exact `termivar-cli` feature gates compiled
into that executable. `compiled` does not mean selected, exercised,
runtime-ready, production-ready, or officially released: profiles and review
options still require their listed explicit inputs. The package version and
feature states are self-reported build metadata, not source authentication.

The CLI's default feature list is empty, while its unconditional scanner
dependency still provides `scanning` and `reporting`. The `release-bundle`
composition marker compiles `artifact-adapter`, `normalization-resilience`,
`graphql-review`, `openapi-review`, `rest-review`, and
`authorization-review`; it does not activate them. It excludes
`ssrf-oast-review`, `legacy-scanner`, `api-adapter`, and `proxy-adapter`.
Enabling the six member features individually can therefore produce the same
member surface states while `release-bundle` remains `not_compiled`.

These excerpts are from real Windows x86_64 development binaries built in
separate directories from source implementation commit
`5bd1260e1d9f57226046a6a955662c32fcad6464` on 2026-09-06. Both reported
`0.10.0-alpha.2`, 20 surface records, and
`runtime_execution: not_performed`:

```text
# cargo build --locked -p termivar-cli
# executable SHA-256: 55d6eec93eb21869ae134e4572564f315430b9b3ee03ab559ec506474493a72d
[compiled] Compiled CLI capabilities (command, preview; implemented)
[compiled] Bounded deterministic scan (command, preview; implemented)
[not_compiled] REST read-only review (scan_option, preview; implemented)
[not_compiled] HTTP API adapter (command, unsupported; unsupported_stub)
```

```text
# cargo build --locked -p termivar-cli --no-default-features --features release-bundle
# executable SHA-256: 35ebb7a766653c94263f589c12e0fda71f44d551a192244de7a10b739b782782
release-bundle=compiled
artifact-adapter=compiled
authorization-review=compiled
graphql-review=compiled
normalization-resilience=compiled
openapi-review=compiled
rest-review=compiled
ssrf-oast-review=not_compiled
```

The hashes identify the two files that were executed; they are not build
attestations. The historical `v0.10.0-alpha.1` archives and earlier pinned
`a29ba40c8cfdc7d0385431ea4d9e374e213ca4e0` source walkthrough predate this
command; the published alpha.2 archives include it. Compiling
`ssrf-oast-review` separately does not close corrective-maintenance F3, which
remains deferred, out of scope, and unresolved.

## Live assessment progress

The unreleased `0.10.0-alpha.3` development source adds opt-in live progress
for an explicit `web-review` assessment:

```bash
termivar scan <AUTHORIZED_TARGET> \
  --profile web-review \
  --progress \
  --format json > assessment.json 2> progress.log
```

The published `v0.10.0-alpha.2` archives do not contain `--progress`. The flag
is rejected for no-profile invocations (including a bare `decision-scan`) and
for `baseline` before secret loading, output reservation, or network
construction. The `decision-scan` alias accepts it when `--profile web-review`
is explicit. It does not enable a scanner capability or add requests.

Progress is a bounded, best-effort presentation channel on stderr. Report
Markdown/JSON on stdout and files selected with `--report-output` or
`--report-dir` keep their existing bytes and schemas. Each ASCII line begins
with `[progress]` and names a coarse lifecycle state such as
`assessment_running`, `composing_report`, `rendering_report`,
`writing_stdout`, `publishing_report`, or a terminal state. Periodic running
snapshots are sampled once per second; a slow sink may cause intermediate
snapshots to be coalesced or dropped rather than delaying the assessment.

The counters are explicitly last-observed accounting snapshots.
`accounted_requests` is cumulative parent-broker request accounting, including
already-accounted child activity; it is not a response count.
`accounted_active_verifications` is a cumulative charged-verification count,
not current concurrency. `subjects_started` counts child-runtime execution
boundaries; `subjects_processed` counts subject states committed for report
projection, not successful subjects or findings. Neither predicts future work.
Before the first runtime checkpoint, unavailable counts are shown as `unknown`
rather than being presented as measured zeroes.
Elapsed milliseconds use a separate monotonic presentation clock. It starts
after runtime construction, immediately before the one assessment analysis,
and ends when the terminal line is prepared after the selected stdout or file
publication succeeds or fails. It therefore includes report composition,
rendering, publication, and progress handoff time; it does not replace, extend,
or alter the runtime deadline clock.

There is no percentage, ETA, endpoint, finding title, severity, vulnerability
verdict, or raw evidence in this stream. A terminal `completed` state means the
selected report output also completed; render or publication failure remains a
distinct `failed` state. On bundle-publication failure, the terminal record can
state whether the manifest commit point was reached, without exposing the
directory. Progress-write failure disables further presentation and does not
change the scan result. If an operating-system stderr write blocks forever,
one detached presentation worker may remain until process exit. A later
diagnostic using the same process stderr lock can then also wait behind that OS
write, so the command cannot promise bounded exit in this host-level failure.
The writer is never used for scan control or backpressure.

## Opt in to WordPress evidence review from source

The unreleased development source has a non-default `wordpress-review` build
feature. It is not in the published alpha.2 archives or the curated
`release-bundle`. Build a separate development executable deliberately:

```bash
cargo build --locked -p termivar-cli --no-default-features --features wordpress-review
```

Against an already running, authorized fixture or exact origin, select the
review explicitly:

```bash
termivar scan <AUTHORIZED_EXACT_ROOT> \
  --profile web-review \
  --wordpress-review \
  --wordpress-context <CONTEXT.json> \
  --wordpress-advisories <CATALOGUE.json> \
  --report-dir <NEW_REPORT_DIRECTORY>
```

Instead of the native Termivar catalogue, an already saved Wordfence V3
Production-format export can be selected explicitly:

```bash
termivar scan <AUTHORIZED_EXACT_ROOT> \
  --profile web-review \
  --wordpress-review \
  --wordpress-plugins-json <WP_CLI_PLUGINS.json> \
  --wordpress-themes-json <WP_CLI_THEMES.json> \
  --wordpress-core-version-file <CORE_VERSION.txt> \
  --wordpress-advisories <WORDFENCE_PRODUCTION.json> \
  --wordpress-advisories-format wordfence-v3-production \
  --wordpress-external-version-profile php-release-subset/v1 \
  --report-dir <NEW_REPORT_DIRECTORY>
```

All local files are optional, but each requires `--wordpress-review`; the saved
inventory files conflict with `--wordpress-context`. External format selection
never fetches the feed or searches for an API key, and omitting it keeps the
native Termivar catalogue contract.
The optional external version profile is accepted only for an explicitly
selected local `wordfence-v3-production` file. Choose `numeric-dotted/v1` or
`php-release-subset/v1` to request that named Termivar interpretation. Omitting
the selector preserves the unresolved v4 behavior; selecting it produces the
strict v5 audit and records `explicit_operator` selection with source semantics
still `not_established`. There is no profile inference or fallback.
WordPress interpretation reuses the complete root HTML already obtained by the
assessment and adds no request or active verification. Generator metadata and
asset paths are hints rather than authenticated installation facts; the context
is an operator declaration, the catalogue is a supplied snapshot, and advisory
applicability stays audit-only. See the
[WordPress evidence review contract](wordpress-review.md) and its clearly
labelled [input examples](examples/wordpress-review/README.md).

## Export one assessment in two formats

The published `v0.10.0-alpha.2` binary and later development builds whose
`scan --help` includes `--report-dir` can create HTML and JSON from one completed
assessment:

```bash
termivar scan <AUTHORIZED_TARGET> \
  --profile web-review \
  --report-dir ./assessment-001
```

Use only an exact origin you are authorized to assess. The parent of
`assessment-001` must already exist as a trusted, private, user-owned directory,
and `assessment-001` itself must not exist. The command neither overwrites nor
reuses an existing file, directory, or link and does not create missing parent
directories. On Windows, the new directory inherits the parent's ACL.
Termivar checks the immediate parent is an existing non-link directory; the
operator supplies the trust/ownership assertion for that parent and its
ancestors.

A successful directory contains exactly `assessment.html`, `assessment.json`,
and `manifest.json`. The runtime runs once, composes one completed typed
assessment, and renders both report formats from it. `manifest.json` is
published last and records exact lengths and hashes for the other two files.
Those hashes identify bytes; they are not a signature or proof of scope. The
payload files can be visible while publication is in progress, so readers must
require and verify the final manifest rather than assume whole-directory atomic
visibility.

`--report-dir` requires explicit `web-review` and cannot be combined with
`--report-format` or `--report-output`. `--format` still selects only the
existing diagnostic encoding for an incomplete/failed run; it does not change
the bundle's fixed HTML and JSON formats. An incomplete run creates no
completion manifest. A crash can leave an incomplete directory, which must not
be silently reused.

The bundled JSON retains the normal assessment schema. Two deliberately chosen
bundles can be compared offline:

```bash
termivar report compare \
  --before assessment-001/assessment.json \
  --after assessment-002/assessment.json \
  --same-scope
```

The published alpha.2 archives include this option. The preserved alpha.1
archives and checked-in first-use captures do not. See the
[full bundle and manifest contract](reporting.md#single-run-report-bundles).

## Verify a saved bundle offline

The published `v0.10.0-alpha.2` binary and later development builds whose
`report --help` includes `verify` can check the fixed three-file bundle without
scanning, launching, or rendering the HTML:

```bash
# Text result.
termivar report verify --dir ./assessment-001

# Structured result.
termivar report verify --dir ./assessment-001 --format json
```

Exit `0` and `integrity_match` mean that the supported directory layout,
manifest contract, exact payload lengths and SHA-256 digests, and the completed
assessment JSON summary matched for the bytes read during this invocation.
Exit `1` and `not_verified` identify an incomplete, unsupported, unreadable, or
mismatched bundle with typed reason codes; checks prevented by an earlier
failure remain `not_checked`. Invalid CLI syntax exits `2`.

Run verification only on a quiescent directory beneath trusted parent
directories. Termivar rejects a linked/reparse-point final directory and
non-regular payloads, but it does not prove every ancestor is trustworthy or
create an atomic filesystem snapshot. The command makes no application writes,
repairs, removals, or permission changes. It reads only `manifest.json`,
`assessment.html`, and `assessment.json`, hashes and validates the same captured
payload bytes, and initializes no scanner, credentials, provider, or network
client.

An integrity match is not a signature or source-authenticity result. It does not
establish original target scope, finding accuracy, remediation, HTML safety, or
HTML-to-JSON semantic equivalence. A consistently edited payload and manifest
can still be internally consistent. The HTML is never executed.

Once checked, compare two deliberately selected assessment payloads with the
existing offline command:

```bash
termivar report compare \
  --before assessment-001/assessment.json \
  --after assessment-002/assessment.json \
  --same-scope
```

The verifier checks one bundle's supported internal consistency; comparison
groups observations and separately relies on the operator's same-scope
assertion. See the
[full verification contract](reporting.md#offline-report-bundle-verification).
The published alpha.2 archives contain both `--report-dir` and `report verify`;
the preserved alpha.1 archives contain neither.

## Open the outputs

A passed run prints `first-use: passed` and retains these files in the selected
output directory:

| File | What it contains |
| --- | --- |
| `default.json` | Actual no-profile `decision-scan/v1` operational output, not a findings report |
| `assessment.json` | Completed root `web-review` assessment from the existing JSON renderer |
| `assessment.html` | Completed root `web-review` assessment from a separate CLI execution using the existing HTML renderer |
| `provenance.json` | Binary hash/version, declared ref/features, host, fixture digest, exact command arguments, exit codes, timings, and output hashes |
| `captures/` | Bounded stdout and stderr for each command, including failure cases |

Open the local HTML file in a browser or inspect the JSON in an editor. The
HTML is self-contained; it does not add scripts, tracking, or external assets.
The JSON and HTML runs have separate invocation records. Do not assume that
independent executions share IDs, timings, or evidence.

See the [genuine, version-labelled example reports](examples/first-use/README.md)
for the tested binary, native platform, exact fixture/report hashes, and a guide
to the actual observations. Downloadable platform archives are not evidence
that each architecture was executed. A local isolated-directory run or hosted
CI run is not a clean-machine certification.

## Read the result accurately

The checked-in Windows alpha.1 sample completed the root assessment and
contains four `informational`, observation-based items: four named response
headers were not observed. Those are observations from the demonstration, not
confirmed vulnerabilities.

`Informational` records an observation. `NeedsReview` asks a human to review
evidence without confirming a vulnerability; the sample does not manufacture
such an item. An action's `Success` outcome means that its objective was
achieved, not that a vulnerability was confirmed.

A default scan is an operational path. An ordinary stop can be `complete` or
`halt` with `no_eligible_action`; it is not an assessment findings report.
A begun-but-incomplete assessment is different from a completed report with no
items. The absence of reported observations does not mean “secure,” “clean,” or
“not vulnerable.”

No optional review flags were supplied. Capabilities that the report does not
name were not demonstrated by this fixture; the guide does not invent
per-capability “passed” or “not vulnerable” statuses. This fixture cannot
establish detection accuracy, exploitability, or comprehensive coverage.
See the [report contract](reporting.md) and
[operational JSON contract](internals/decision-scan-json-v1.md).

## What acceptance checks

The same runner checks the existing interfaces without modifying CLI behavior:

- Actual version and documented help syntax.
- The no-profile operational path and completed root JSON/HTML assessments.
- Refusal to replace an existing report: its original bytes remain unchanged.
- A separate preflight failure: nonzero exit and no success report or fixture I/O.
- A begun local `/example` run that returns the existing incomplete diagnostic
  after fixture I/O, with no partial success report.
- Bounded captures, report privacy, and cleanup of the runner's own resources.

Expected failing CLI cases are recorded individually; they do not mean the
overall acceptance failed when their refusal/incomplete behavior matches the
checks. An unexpected failure makes the runner exit nonzero. Inspect
`provenance.json` and `captures/` when they exist; early prerequisite failures
may occur before an output directory is created. Do not reuse a prior output
directory or treat an earlier successful report as the result of a failed run.

Raw provenance and diagnostics may contain local paths. Keep them local or
review them before sharing. Published sample provenance replaces only the
executable path fields listed in its normalization record with
`<LOCAL_BINARY>`; report bytes, observations, counts, completion state, and
errors are not rewritten. Raw captures are retained as local/CI evidence.

## Further reading

- [Distribution and build choices](DISTRIBUTION.md)
- [Feature lifecycle](https://github.com/ITherso/termivar/blob/main/FEATURES.md)
  and [runtime map](internals/runtime-map.md)
- [Reporting](reporting.md) and [architecture](architecture.md)
- [Credential-input limits](internals/credential-input.md) and
  [maintenance ledger](audits/native-oast-corrective-maintenance.md);
  F3 remains deferred, out of scope, and unresolved
- [Scanner SDK](sdk.md), [plugin contracts](plugin.md), and
  [preserved scanner history](history/historical-scanner-salvage.md)
- [Testing](TESTING.md) and
  [contribution guide](https://github.com/ITherso/termivar/blob/main/CONTRIBUTING.md)
