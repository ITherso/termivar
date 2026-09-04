# Fuzzing

The `fuzz/` package contains six Termivar-owned semantic targets plus five bounded
upstream-parser targets. `html_form_controls`, `expression_semantics`, and
`declarative_policy_wire` exercise extraction and declarative-policy contracts;
`decision_loop_authority` exercises adaptive planner authority, and
`oast_correlation` exercises the transport-free correlation state machine, and
`native_oast_provider` exercises the self-hosted provider's bounded input
contracts without network I/O. The parser
targets are dependency-level signals and must not be reported as Termivar
decision-runtime coverage.

## Setup

```bash
cargo install cargo-fuzz --version 0.13.2 --locked
cargo fuzz list
cargo fuzz run html_form_controls
cargo fuzz run expression_semantics
cargo fuzz run declarative_policy_wire
cargo fuzz run decision_loop_authority
cargo fuzz run oast_correlation
cargo fuzz run native_oast_provider
```

Every pull request replays the committed semantic corpora, runs the deterministic
structured OAST regression matrix, and compiles all Termivar-owned targets. The
`Scheduled Fuzzing` workflow runs all eleven targets in bounded weekly campaigns
and when fuzz harnesses change on `main`. Every target uploads its libFuzzer log
and a structured campaign summary for 90 days; failures also retain crash
artifacts. This provides regression pressure, not proof of parser or
decision-runtime safety.

Run fuzzing on a dedicated machine or bounded CI job. Start with a small, non-sensitive seed corpus. Crashes must preserve the minimized input and exact commit SHA.

## Targets

| Target | Ownership | Contract |
| --- | --- | --- |
| `html_form_controls` | Termivar | Bounded HTML sample to exact, names-only, sorted and deduplicated form-control observations |
| `expression_semantics` | Termivar | Exact TextList truth table, truthful contributing evidence IDs, deterministic evaluation, and bounded expression round trips |
| `declarative_policy_wire` | Termivar | One-field semantic corruption rejects or reconstructs an exactly equivalent historical policy |
| `decision_loop_authority` | Termivar | Adaptive scheduling cannot bypass registration, host suppression, requirements, risk, budget, prerequisites, executor identity, or claim policy; errors are atomic |
| `oast_correlation` | Termivar | Host-minted token reuse, exact case/correlation binding, protocol grants, expiry/cancellation, bounded poll permits, opaque event-key replay suppression, and atomic batch failure semantics |
| `native_oast_provider` | Termivar | Exact public-origin, loopback-bind, strict session-request, opaque-identity, callback-path identity, and cursor parsing; checked resource limits; administrator-secret validation/redaction; raw-free state transitions; and fixed provider regressions without network I/O |
| `http_parser` | Upstream | `httparse` request parser survival |
| `json_parser` | Upstream | `serde_json` value parser survival |
| `yaml_parser` | Upstream-only dependency | `serde_yaml` value parser survival |
| `xml_parser` | Upstream-only dependency | `quick-xml` event reader survival |
| `text_parser` | Upstream | URL and UTF-8 parser survival |

`html_form_controls` compiles the same private extractor source used by
`HttpEvidenceExecutor`; no production API is made public for fuzzability. Its
structured oracle computes expected names independently from the parser output.
It asserts exact HTML `name` preservation (including whitespace), independent
coverage of the `input`/`select`/`textarea` branches, HTML element namespaces,
unqualified `name`-attribute selection, integration-point behavior, and
exclusion of empty names and non-control/decoy content. Raw malformed inputs
must classify the 64-KiB parse boundary exactly, remain deterministic, and
return sorted/deduplicated non-empty observations. The target also protects the
names-only privacy boundary and accepts at most 64 KiB of raw input.

`expression_semantics` builds bounded typed evidence through public Termivar APIs.
Its independent oracle requires complete, case-sensitive TextList element
equality; scalar text, padded names, case changes, and substring-only values do
not contribute. Repeated evaluation and accepted expression serialization must
be identical, and a nested expression is limited to 32 levels and 64 nodes in
the harness.

`declarative_policy_wire` starts from valid selectors, calibrations, reasoning
rules, verification rules/cases, adaptation rules, and directives. It deletes,
misspells, nulls, conflicts, or corrupts one semantics-bearing field. The result
must reject unless it is a documented historical representation that
reconstructs exactly the original policy and canonicalizes on the next write.
The expression and declarative-policy targets cap inputs at 16 KiB and semantic
strings at 256 bytes.

`decision_loop_authority` converts at most 16 KiB of input into one of fourteen
small, network-free DecisionLoop scenarios. It runs every scenario twice and
compares normalized session, Experience, command, and hypothesis semantics. An
unregistered, suppressed, ineligible, over-risk, over-budget, or dependent
scheduled action cannot dispatch; missing host context fails closed for both
schedule and retry directives. Active continuation is reauthorized against
dynamic host suppression, and authorization observes a conclusive outcome's
prospective hypothesis state. Every returned authorization error must leave
the session, Experience store, and motivation hypothesis exactly unchanged. An
eligible independent action must carry its registered executor and its own
Motivation or KnowledgeOnly transition policy. A replay cannot continue an
outstanding action after that action is absent from the planner registry. It
also rejects a legacy/default replay that would broaden a currently registered
KnowledgeOnly action into hypothesis-transition authority.

`oast_correlation` converts a structured prefix of an input of at most 4 KiB
into one of twelve pure, provider-neutral scenarios. The input independently
selects the token and event-key bytes, monotonic schedule, expiry slack,
authority limits, and poll budget. An expectation table defined independently
from the implementation requires the exact error variant, registration and poll
counters, active or terminal state and time, accepted/unique/duplicate counts,
atomic failure behavior, and reduced receipt semantics for each scenario. A
second run must reproduce that same expected observation. The scenarios cover
token reuse, wrong case/correlation routing, protocol grants, expiry,
cancellation, spent poll permits, duplicate keys, conflicting protocol
families for one event key, and unique-event limits. The harness performs no
network, provider, clock, random, reporting, or scanner-runtime work.

`native_oast_provider` accepts at most 4 KiB and routes a bounded prefix through
the exact production public-origin, loopback-bind, provider-limit,
administrator-token, session-request, opaque-identity, and cursor constructors.
Callback-shaped inputs and complete Authorization values are reduced through
the production fixed-route and redacted Bearer parsers. Repeated parsing must
classify identically;
successful origins remain canonical HTTPS DNS origins, successful binds remain
loopback, limits remain inside every hard ceiling, and secret Debug/error text
cannot contain supplied token material. Its fixed regressions keep IP-literal,
localhost, userinfo, non-root path, query, fragment, wildcard, public-bind, and
unspecified-bind rejection in every campaign. A bounded in-memory state model
also registers, allocates, records and deduplicates GET/HEAD observations,
polls, and cleans up while comparing only raw-free result shape; provider-minted
random identities are never used as an oracle. The harness does not start the
HTTP provider, read secret sources, or perform network I/O.

## Semantic corpus and reproduction

Reviewed seeds under `fuzz/corpus/html_form_controls/` include the minimized
whitespace-normalization reproducer, exact and substring-only convention names,
real/empty/duplicate/Unicode controls, quote-state spoofing, raw-text/comment
decoys, values, character references, malformed/truncated markup, a long name,
modest nesting, SVG/MathML control lookalikes, genuine HTML integration-point
descendants, foreign-content re-entry, and distinct identities for every
supported control tag. Generated hash-named corpus files remain ignored until
they are deliberately reviewed and promoted.

`fuzz/corpus/expression_semantics/` contains exact `_token`, substring-only,
padded, case-sensitive `_METHOD`, scalar/list mismatch, duplicates, Unicode,
depth-boundary, valid nested, malformed nested-expression, empty `all`/`any`,
and blank text-matcher examples.
`fuzz/corpus/declarative_policy_wire/` contains one reviewed seed for every
corruption scenario: matcher, aggregation, reasoning condition, verification
scope/case guard, adaptation condition, and pipeline directive loss or typo.
`fuzz/corpus/decision_loop_authority/` contains one reviewed seed for each
authority boundary: unregistered and host-suppressed scheduling, unmet
requirements, risk and budget rejection, prerequisite rejection, eligible
Motivation and KnowledgeOnly dispatch, context-free schedule/retry, prospective
motivation rejection, active host suppression, and a legacy/default replay that
references an action no longer registered with the planner or broadens a
KnowledgeOnly case into hypothesis-transition authority.
The harness replay also constructs 96 deterministic, owned 80-byte OAST seeds:
all twelve scenarios crossed with eight boundary patterns. Every seed populates
the complete token, event key, timing, and bound-selector prefix consumed by the
OAST model rather than relying on fallback bytes.
It separately constructs 96 deterministic, owned 96-byte native-provider
seeds by crossing twelve scenario selectors with eight boundary patterns. They
exercise all provider-input oracle classes without containing real credentials
or public provider addresses. Sixteen additional exact route and Bearer seeds
pin canonical and adversarial production-parser cases.
Generated hash-named files in every corpus remain ignored until reviewed.

Replay all committed seeds without libFuzzer:

```bash
cargo test --manifest-path fuzz/harness/Cargo.toml --locked
```

Replay or minimize one retained finding:

```bash
cd fuzz
cargo fuzz run html_form_controls artifacts/html_form_controls/<artifact>
cargo fuzz tmin html_form_controls artifacts/html_form_controls/<artifact>
cargo fuzz run expression_semantics artifacts/expression_semantics/<artifact>
cargo fuzz tmin declarative_policy_wire artifacts/declarative_policy_wire/<artifact>
cargo fuzz run decision_loop_authority artifacts/decision_loop_authority/<artifact>
cargo fuzz tmin decision_loop_authority artifacts/decision_loop_authority/<artifact>
cargo fuzz run oast_correlation artifacts/oast_correlation/<artifact>
cargo fuzz tmin oast_correlation artifacts/oast_correlation/<artifact>
cargo fuzz run native_oast_provider artifacts/native_oast_provider/<artifact>
cargo fuzz tmin native_oast_provider artifacts/native_oast_provider/<artifact>
```

Scheduled campaigns use an explicit 60-second budget and 1024-MiB RSS limit with
a recorded deterministic seed. HTML and upstream targets use at most 64 KiB and
five seconds per input; semantic policy targets use at most 16 KiB and two
seconds. A timeout, semantic assertion failure, panic, excessive allocation, or
sanitizer finding requires the same minimize-classify-regress-fix triage as a
normal test failure.

Fuzz harnesses should have no network, filesystem, or ambient-clock
dependencies. The native-provider state oracle deliberately calls the exact
production OS-CSPRNG identity path rather than introducing a deterministic
identity mint; it normalizes every generated identity away and asserts only
transition classes and bounded counts. No random identity bytes participate in
an expected value. A parser rejection is not a crash; panics, hangs, excessive
allocation, and sanitizer findings require triage.

## Published reports

Reports committed under `docs/reports/fuzzing/` record the exact commit, bounded runtime, target outcomes, corpus counts, and workflow provenance. A report is published only after all target jobs complete; absence of a crash in a bounded run is not a safety claim.

- [`7515b79`: five 60-second campaigns, 32,500,714 executions, no observed crashes](reports/fuzzing/7515b79.md)
