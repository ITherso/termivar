# Getting started

This unreleased development source line (package version `0.10.0-alpha.2`) is
an experimental Rust security-testing project. The published
`v0.10.0-alpha.1` prerelease does not include later `main` changes. Build a
reviewed, pinned commit; it is not production-ready and must be run only
against systems you own or are explicitly authorized to test.

This guide covers the default deterministic CLI and the separately compiled
historical runner. It does not describe a dashboard, bound API service,
TLS-intercepting MITM proxy, durable distributed control plane, team service,
or cloud control plane because those are not supported runtime products today.

## Prerequisites

- Rust 1.88 or newer ([rustup](https://rustup.rs/))
- Git
- An authorized, reachable HTTP(S) origin

Docker is optional. PostgreSQL, Redis, Node.js, and a browser are not required to build or run the CLI scan commands.

## Build from source

```bash
git clone https://github.com/ITherso/termivar.git termivar
cd termivar
REVIEWED_COMMIT="REPLACE_WITH_THE_REVIEWED_FULL_COMMIT_SHA"
test "$REVIEWED_COMMIT" != "REPLACE_WITH_THE_REVIEWED_FULL_COMMIT_SHA"
git checkout --detach "$REVIEWED_COMMIT"
test "$(git rev-parse HEAD)" = "$REVIEWED_COMMIT"
cargo build --locked -p termivar-cli
cargo run -p termivar-cli --locked -- --help
```

The root manifest is a virtual workspace. The CLI package is `termivar-cli`; its binary is named `termivar`.

## Run the deterministic runtime

`scan` is the current deterministic Surface-B preview and the default product
command. With no explicit profile it retains the conservative single-resource
behavior and compatibility output:

```bash
cargo run -p termivar-cli --locked -- scan https://authorized.example.test
```

`example.test` is a reserved placeholder and will not normally resolve. Replace it with an exact origin you own or have explicit permission to assess.

The command:

- bootstraps bounded HTTP evidence for one authorized origin;
- reasons over typed evidence and subject-scoped hypotheses;
- selects eligible actions using deterministic utility, cost, risk, requirements, prerequisites, and suppression policy;
- executes built-in requests through one redirect-disabled, metered broker;
- applies passive or active verification under the action's claim policy;
- stops under fixed request, byte, wall-time, action-attempt, and no-progress limits.

It emits operational decisions and outcomes, not deterministic-runtime findings or vulnerability declarations.

### Explain mode

```bash
cargo run -p termivar-cli --locked -- scan https://authorized.example.test --explain
```

The expanded text includes hypotheses, selected and excluded actions, dispatches, outcomes, and terminal reasoning.

### JSON diagnostics

```bash
cargo run -p termivar-cli --locked -- scan https://authorized.example.test --format json
```

The JSON document retains the historically named schema [`decision-scan/v1`](internals/decision-scan-json-v1.md). It already carries full diagnostics, so `--format json` and `--explain` cannot be combined. `decision-scan` remains a deprecated, discoverable command alias for `scan`; it runs the same implementation and produces identical stdout and stderr. Selecting no profile is the compatibility state; neither new profile silently changes this wire document.

### Explicit product profiles

The strict `venom.scan-profile/v1` contract implements exactly two named
profiles:

```bash
cargo run -p termivar-cli --locked -- scan https://authorized.example.test --profile baseline
cargo run -p termivar-cli --locked -- scan https://authorized.example.test --profile web-review
```

`baseline` explicitly selects the same conservative single-resource decision
behavior and emits the additive `web-assessment/v1` profile audit.
`web-review` is the only exact-origin opt-in. It uses stable bounded discovery,
then runs bounded semantic extraction, defense observation and shadow planning,
passive security-header/cookie review, and the closed native differential
catalog over committed evidence. All endpoint work shares one runtime budget,
redirect-disabled request broker, cancellation authority, and exact-origin
authorization policy. Cross-origin references are never followed, and
discovery of a URL, form, control name, or query-parameter name is knowledge
rather than a vulnerability result.

The passive review covers HSTS, CSP, X-Content-Type-Options,
Referrer-Policy, Permissions-Policy, and value-free cookie attributes. It emits
only `Informational` assessment items. Native review adds a matched CORS pair
on the authorized starting resource without replacing eligible standard work;
both CORS legs must have successful status classes. When that starting URL names a recognized
navigation query parameter, it also adds a matched redirect/reflection pair
using a deterministic `.invalid` candidate after discarding the supplied
value. Only 301/302/303/307/308 are redirect candidates, and they are observed
but not followed. Complete credentialed CORS,
exact candidate-specific redirect, and dangerous-context reflection
relationships are at most `NeedsReview`; ordinary exact reflection remains
`Informational`. No native assessment capability can produce a `Confirmed`
item, and no browser execution is performed.

To add the optional exact-root authorization-context comparison, load one
complete `Authorization` header value into a secret source out of band, then
name that source rather than placing the value in process arguments:

```bash
cargo run -p termivar-cli --locked -- scan https://authorized.example.test \
  --profile web-review --report-format json --auth-env TERMIVAR_AUTH_CONTEXT
cargo run -p termivar-cli --locked -- scan https://authorized.example.test \
  --profile web-review --report-format json --auth-file /secure/path/termivar-auth-context
```

`--auth-stdin` reads through EOF and is also supported; the invoking host must
therefore bound its own input lifecycle. `--auth-file` accepts only a regular,
non-symlink file. The three sources are mutually exclusive, bounded to the
scanner's compiled 4 KiB payload-artifact ceiling, and consumed only after
profile, exact-root, authenticated-transport, and obvious report-output
validation. Credentialed review requires HTTPS, with numeric-IP loopback HTTP
reserved for deterministic local fixtures.
Termivar does not expose a raw `--authorization` option. It sends an anonymous
control and an authorized candidate through the same global assessment
authority. Equal JSON visibility emits no item; a complete difference is one
atomic `NeedsReview` comparison, not confirmation of broken authorization.
Credentials and raw response bodies are not serialized or logged.

For completed reports, start `web-review` at the exact origin root (`/`). The
historical root identity remains `authorized-root@1`. Eligible discovered
exact-origin subjects use an opaque `discovered-resource@1` identity derived
from canonical structure without query values or readable path material. A
non-root starting target still becomes typed incompleteness.

Completed `web-review` runs use `venom-rendered-assessment/v1`. The normal text
selection maps to Markdown, and `--format json` maps to assessment JSON because
the profile was explicitly selected. Choose another central renderer with
`--report-format`:

```bash
cargo run -p termivar-cli --locked -- scan https://authorized.example.test \
  --profile web-review --report-format csv
cargo run -p termivar-cli --locked -- scan https://authorized.example.test \
  --profile web-review --report-format html --report-output assessment.html
```

`--report-format` accepts `json`, `csv`, `html`, or `markdown` and requires
`web-review`. `--report-output` requires an explicit report format. It publishes
a new file through a same-directory temporary file and hard link, never
overwrites an existing destination, and returns nonzero if the filesystem
cannot provide those semantics. The file contents are synchronized before
publication, but directory-metadata crash durability is best effort.

If a `web-review` run is incomplete or fails after starting, Termivar emits a
redacted `web-assessment/v2` diagnostic audit to stdout, marks assessment items
unavailable, returns nonzero, and creates no report artifact. It never presents
a partial or truncated report as completed output.

### Safe local smoke target

For a network-isolated smoke run, serve a temporary directory on loopback in one terminal:

```bash
python3 -m http.server 8088 --bind 127.0.0.1
```

Then run Termivar in another terminal:

```bash
cargo run -p termivar-cli --locked -- scan http://127.0.0.1:8088
```

This proves command wiring and output shape; it is not a meaningful security assessment.

## Legacy ordered scanner

The historical ordered runner is not present in a default build. To use it, compile the explicit feature and acknowledge its heuristic claim boundary:

```bash
cargo run -p termivar-cli --locked --features legacy-scanner -- legacy-scan \
  https://authorized.example.test --acknowledge-legacy-heuristics
```

It runs the historical phase pipeline. Its crawler, wordlist-based directory
discovery, and parameter discovery share an exact-origin, redirect-disabled
authority with configurable finite depth, page, request, request-timeout,
wall-time, cumulative-body, and per-response-body limits. Those phases stage
typed endpoint/form state atomically. Directory discovery calibrates two
stable randomized nonexistent-path controls for each eligible path shape;
parameter discovery requires a
baseline/control/candidate/identical-replay differential. Their records are
informational observations, not vulnerability confirmation.

Wordlist-based directory discovery is still off within this opt-in runtime. The
additional `--legacy-directory-fuzz` option enables it; use it only when target
authorization and expected load are clear. Phases five through nine use a
second exact-origin, redirect- and retry-disabled authority with finite
`VerificationLimits`. Reproduced SQL behavior and template arithmetic can
project only knowledge-only `NeedsReview`; exact reflection remains `Unknown`.
The CLI's phase-eight and phase-nine defaults are inert. SDK hosts can opt into
a benign local-file canary or OOB URL delivery, but XXE remains disabled and a
probe response is not callback evidence.

Phase one and custom extensions can still perform direct network I/O outside
both scoped authorities and `RuntimeBudget`, so the CLI reports the whole run
as `Unmetered` and prints that warning before execution. Raw phase prose and
evidence details are withheld at the public boundary. See
[ADR 0016](adr/0016-bound-legacy-discovery-authority.md) and
[ADR 0018](adr/0018-bound-legacy-verification-authority.md).

`scan` and its `decision-scan` alias are the same deterministic engine. `legacy-scan` is a different engine; its results, accounting, and claim semantics must not be compared as though it were an output mode of `scan`.

## Understanding deterministic output

| Term | Meaning |
| --- | --- |
| Observed | Present in bounded typed evidence |
| Supported | Deterministic reasoning supports a hypothesis |
| Confirmed | A verifier-authorized transition occurred |
| Success | The action objective completed; confirmation may still be forbidden |
| NeedsReview / Unknown | Evidence does not authorize a terminal claim |

For product-facing `AssessmentItem` values, an observation can project only as
`Informational`; a complete matched differential can justify `NeedsReview`;
and `Confirmed` requires a case-correlated verifier-owned transition that the
claim policy permits. Missing, cross-case, blocked, failed, or KnowledgeOnly
evidence cannot be upgraded to `Confirmed`.

For example, collecting PHP-style form-control names or Sanctum-compatible cookie names is KnowledgeOnly. The action can succeed while its motivating technology hypothesis remains Supported rather than Confirmed.

## Optional normalization-resilience review

The normalization review is absent from default builds. Compile the matching
CLI feature and opt in at runtime only for an authorized `web-review` target:

```bash
cargo run -p termivar-cli --locked --features normalization-resilience -- \
  scan https://authorized.example.test \
  --profile web-review \
  --normalization-resilience
```

The flag is rejected with no profile or with `baseline`. V1 may select one
typed HTML token-case or horizontal-tab representation only after the canonical
inert XSS candidate created candidate-specific defensive engagement. It reuses
the parent pair, sends one transformed candidate and one distinct replay under
the same shared budget, and requires both to reproduce the same inert DOM
semantics. Its ceiling is `NeedsReview` / `KnowledgeOnly`; a `403` followed by a
`200`, or a WAF fingerprint by itself, is not a bypass result. See the
[normalization-resilience contract](internals/normalization-resilience.md).

## Optional CLI adapters

Default builds expose none of `artifact`, `api`, or `proxy`. They can be
compiled as explicit adapters, but they are not scan alternatives:

- `cargo run -p termivar-cli --locked --features artifact-adapter -- artifact scan-file --signatures artifact-signatures/lab/termivar-canary/signatures.toml --input ./authorized-sample.bin --format json` performs one bounded read-only scan of one explicit regular file. It does not recurse, acquire process memory, write files, issue network requests, or turn observations into malware/vulnerability verdicts.
- `cargo run -p termivar-cli --locked --features api-adapter -- api --addr 127.0.0.1:8080` is unsupported and exits nonzero: the library has a health router, but no listener is implemented.
- `cargo run -p termivar-cli --locked --features proxy-adapter -- proxy --addr 127.0.0.1:8081 --upstream 127.0.0.1:9081` starts an experimental TCP relay to the explicitly selected upstream. It does not implement HTTP `CONNECT`, TLS termination, generated certificates, or request inspection.

Lua execution and distributed coordination are implemented Experimental,
opt-in host-library APIs with no repository runtime caller. Dashboard,
monitoring, and compliance modules remain disconnected or host-owned. The two
built-in scan profiles are CLI-wired; custom profile files are not supported.
See the [runtime map](internals/runtime-map.md) before treating any optional
module as executable product behavior.

## Validate a checkout

```bash
cargo +1.88.0 fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo xtask architecture
cargo xtask docs
```

The last command requires the documentation dependencies from `requirements-docs.txt`.

CI adds deliberately scoped evidence beyond those local commands. A Rust
`1.88.0` matrix builds and smoke-tests the default CLI plus loopback path,
scope, redirect, wire, and report-output contracts on Ubuntu, Windows, and
macOS. It is not platform certification or an all-features release claim. The
`compat/current-head/` workspace uses one dedicated lockfile and separately
tests four same-head packages for default core, deterministic
assessment/reporting, the Legacy `ScannerSdk` facade, and plugin API 0.2; it
does not prove cross-version compatibility or external adoption.

The loopback endpoint harness also has [initial controlled evidence](reports/benchmarks/27321ef-endpoint-assessment.md)
for source commit `27321efbbf49cb2adbc72afb699d1b31ea407486` from
[workflow run 33292247976](https://github.com/ITherso/venom/actions/runs/33292247976),
with a [validated JSON record](reports/benchmarks/27321ef-endpoint-assessment.json).
It is one runner-local measurement set, not an SLA, accepted repeatable
baseline, or capacity certification.

## Extend Termivar

The deterministic assessment/reporting surface and native plugin API 0.2 are
Preview. `ScannerSdk` and its ordered phase runner are a Legacy facade. The
generated scanner and plugin starters compile in CI, but generation does not
change those lifecycle labels:

```bash
cargo install cargo-generate
cargo xtask generate scanner my-scanner
cargo xtask generate plugin my-termivar-plugin
```

They are source-level, opt-in library integrations, not runtime-loaded
extensions for the default deterministic `scan`. The scanner starter uses the
Legacy phase facade; new product capability belongs in the deterministic
runtime rather than that runner. Termivar ships no stock detector plugins; the
generated Preview plugin records an INFO-only trait-boundary observation
through host-owned policy and makes no security claim. Read the
[Scanner SDK](sdk.md), [plugin guide](plugin.md), and
[plugin API policy](plugin-api-policy.md) before depending on pre-stable
contracts.

## Next steps

- [Root project overview](https://github.com/ITherso/termivar#readme)
- [Runtime map](internals/runtime-map.md)
- [Architecture](architecture.md)
- [Decision runner](internals/decision-runner.md)
- [Web execution](internals/web-execution.md)
- [Web verification](internals/web-verification.md)
- [Feature lifecycle](https://github.com/ITherso/termivar/blob/main/FEATURES.md)
- [Project status](https://github.com/ITherso/termivar/blob/main/PROJECT_STATUS.md)
- [Security policy](https://github.com/ITherso/termivar/blob/main/SECURITY.md)
