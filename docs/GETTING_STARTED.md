# Getting started

This walkthrough runs the actual CLI against a tiny, repository-owned static
demonstration. It is credential-free and uses only numeric loopback
`127.0.0.1`. It demonstrates command behavior and report reading, not detection
accuracy or the security of an application.

Choose one binary first:

- [Published prerelease: v0.10.0-alpha.1](DISTRIBUTION.md#try-the-published-prerelease):
  manually download, verify, inspect, and extract your platform archive. No
  Rust toolchain is required.
- [Development source: 0.10.0-alpha.2](DISTRIBUTION.md#build-from-source):
  build package `termivar-cli` from the reviewed full commit
  `a29ba40c8cfdc7d0385431ea4d9e374e213ca4e0` in a separate source tree.

The older archives do not include maintenance from PRs #109–#111 and are not
recommended for credentialed or production use. The
[distribution comparison](DISTRIBUTION.md) records the exact release identity
and build features. Neither build is independently audited or production-ready.

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
  --binary ./termivar-alpha1/termivar \
  --output first-use-release-output \
  --source-ref v0.10.0-alpha.1 \
  --build-features release-bundle \
  --expect-version 0.10.0-alpha.1
```

Windows PowerShell:

```powershell
python scripts/first_use.py --binary .\termivar-alpha1\termivar.exe --output first-use-release-output --source-ref v0.10.0-alpha.1 --build-features release-bundle --expect-version 0.10.0-alpha.1
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

## Export one development assessment in two formats

A development `0.10.0-alpha.2` binary whose `scan --help` includes
`--report-dir` can create HTML and JSON from one completed assessment:

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

This option belongs to development source containing the feature; the published
`v0.10.0-alpha.1` archives and their checked-in first-use captures do not have
it. See the [full bundle and manifest contract](reporting.md#single-run-report-bundles).

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
