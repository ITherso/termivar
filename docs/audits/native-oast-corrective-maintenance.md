# Native OAST corrective maintenance

This is a repository maintenance record, not an independent security audit or
an exploitability assessment. Static findings were supplied by the maintainer;
each disposition below distinguishes inspection from executed regression proof.

## Reviewed baseline and delivery

- Reviewed and fetched main: `3de3d32f9cb0b6b76cd9f7a3c24ce4557d848b29`.
- Development version: `0.10.0-alpha.2`. GitHub release metadata, checked again
  on 2026-09-05, confirms the published [v0.10.0-alpha.1 prerelease](https://github.com/ITherso/termivar/releases/tag/v0.10.0-alpha.1)
  dated 2026-09-03; no alpha.2 release is present.
- Worktree was clean. Open dependency-update PRs and unrelated branches remain
  outside this work.
- PR A branch: `agent/oast-lifecycle-transport-hardening`.
- PR A: [#109](https://github.com/ITherso/termivar/pull/109), tested and landed
  `b8c0ae2630b541ac04733e4f2701423654f740a8`. All 14 required contexts passed;
  aggregate coverage 89.87%, patch 100.00% (187/187). Both task branches were
  deleted and protected main advanced by exact-SHA fast-forward.
- PR B: [#110](https://github.com/ITherso/termivar/pull/110), based on that exact
  PR A SHA and tested/landed as `f0b2889c07fe765f8b2f7bdf785725edda209b67`.
  The [exact-head landing receipt](https://github.com/ITherso/termivar/pull/110#issuecomment-5551145983)
  records all 14 strict required contexts, all 28 applicable Actions contexts
  and all six workflow runs successful. Aggregate coverage was 64,678/71,944
  (89.90%); patch coverage was 159/166 (95.78%). One test-only Clippy repair
  round was needed. Protected main advanced by exact-SHA fast-forward;
  the local and remote task branches were deleted.
- PR C starts from that landed SHA on `agent/credential-intake-hardening`.
  Credential-input repairs are implemented; final CI/landing evidence remains
  pending.

## Finding ledger

| ID / source | Disposition | Observed behavior and intended contract | Regression evidence / change / limits |
| --- | --- | --- | --- |
| F1 — `termivar-oast/src/state.rs`, `register_bearer`, `poll_bearer`, `cleanup_bearer`, `SessionState` | Confirmed defect; repair in PR A | Expiration stops acceptance but abandoned sessions remain in the retained-capacity map indefinitely. Acceptance expiry and finite result retention must be separate. | A dropped-registration-response test failed against old behavior with explicitly advanced monotonic time. PR A adds a 120-second result window after acceptance expiry, checked deadline arithmetic and authenticated lazy reclamation over at most 256 retained entries. Results are not erased at the expiry instant while idle. |
| F2 — `termivar-oast/src/server.rs`, `serve_listener`, `serve_connection`, `AppState::admit` | Confirmed defect; repair in PR A | Connection count is bounded, connection lifetime is not explicitly bounded; handler admission occurs after body extraction. | A single benign incomplete-header duplex test failed against old behavior under paused Tokio time. PR A places admission before body extraction and bounds header, request/body, I/O idle and total connection lifetimes. No load test or target application is used. |
| F3 — `web_runtime/ssrf_oast_runtime.rs`, polling phase completion | Deferred / out of scope / unresolved | The maintainer explicitly excluded active SSRF replay/verification behavior from this continuation. | No phase-completion fix or success oracle is added. The polling region, receipt-order completeness check and public review-outcome enum remain byte-identical after newline normalization. This finding is not closed or rejected. |
| F4 — `termivar-oast/src/client.rs::validate_response_head`, `native_oast_provider.rs::client_failure`, runtime audit boundary | Confirmed defect; repaired in PR B | Unexpected statuses and construction/transport failures can be mislabeled as authentication failures, and early failures lack typed audit detail. | Synthetic 401-vs-429 and local-credential-vs-remote-auth regressions failed before repair and passed afterward. Add non-exhaustive HTTP metadata without changing existing public client error variants; retain separate optional first-provider/cleanup diagnostics through the existing serializable library audit. No response prose, new CLI renderer or protocol/digest identity change. |
| F5 — provider receipt/count assignments in `ssrf_oast_runtime.rs`; permit dispatch accounting | Confirmed defect; repaired and landed in PR B | A failure receipt can exist before budget admission. Receipt-vector length is not the charged HTTP-operation count. | All five audit count paths now read the permit counter. Synthetic tests distinguish recorded attempts, admitted requests, possibly-dispatched operations and body EOF. Failure receipts and successful-path ordering checks remain. Local adapter execution was blocked by Application Control; exact-head CI passed as recorded in the PR B landing receipt. |
| F6 — both CLI/provider `open_regular_file` implementations | Conditional local-path risk confirmed by inspection; repair implemented in PR C, CI pending | Separate pathname inspection and open do not atomically reject a substituted link or establish object identity. | Both loaders now open with platform no-follow flags and validate the same handle before bytes. Final-component protection requires trusted parents and does not establish immutable contents or hard-link provenance. Baseline evidence is inspection only, not an executed red test; new deterministic tests compiled but local execution was blocked. No filesystem exploitation or privileged test result is claimed. |
| F7 — CLI `read_environment`, `read_bounded_line_source` | Confirmed intake-buffer defect by inspection; repair implemented in PR C, CI pending | Some owned raw buffers can be dropped on oversize/read error before entering a zeroizing wrapper. | CLI input is guarded before fallible validation/read, with initialized storage for partial errors, a guarded overflow probe and suffix wiping before truncation. The guarantee ends at constructor handoff; downstream root/principal copies remain unchanged. Provider input already used `Zeroizing` and now also wipes the removed suffix. Deterministic tests compiled; local execution was blocked, not passed. |
| F8 — `PROJECT_STATUS.md`, `docs/DISTRIBUTION.md`, affected provider documentation | Mixed: factual corrections in PR C; already-corrected statements preserved | PROJECT_STATUS omitted the current published prerelease and still described the ScanContext release prerequisite as unmet. An installer sentence also depended on an obsolete release condition. | GitHub release metadata and alpha.1 tagged source confirm the narrow corrections. README and distribution release-status descriptions from `61d08b3` are retained. PR A lifecycle/transport and PR B diagnostic/accounting documentation are preserved. The shared credential-input contract states final-component and intake-memory limits; PR C final verification remains pending. |

## PR A contract

Acceptance ends at the declared session lifetime. Existing results remain
pollable subject to the existing authentication and poll budgets until
`acceptance expiry + 120 seconds` (exclusive). A later valid administrator-
authenticated registration or authenticated session allocation/poll/cleanup
reclaims expired retained entries. Invalid registration input does not sweep.
Each sweep visits at most the
existing 256-entry hard cap, so no cursor can starve a later entry. Live and
still-retained sessions cannot be evicted to admit a new registration.
Removal drops and zeroizes the owned token digest. A reclaimed session uses
the existing `SessionNotFound` result and generic HTTP mapping; callback
responses remain non-reflective. No background reclamation task is introduced.

HTTP/1 uses a Tokio-backed 10-second header timer, a 15-second whole request
deadline including body extraction and handler processing, a 30-second I/O
inactivity ceiling, and a 120-second absolute backend connection lifetime.
Healthy requests can reuse a connection. Hyper's header timer can close a
silent keep-alive connection before the outer inactivity limit; reverse proxies
must tolerate this normal connection rotation. Immediate bounded admission
occurs before extraction; no state mutex is held during network body reads.
Timeout responses carry no request material and close the connection.

Client cancellation, expired authority and exhausted parent budget remain
terminal. They are not bypassed for cleanup. Provider retention recovers
abandoned capacity when client cleanup cannot run. Local closure, attempted
cleanup, transport admission and verified remote deletion are distinct facts.

## Validation record

Local regressions use only provider-owned state, temporary resources and benign
in-memory HTTP transports. The installed ordinary GNU Rust 1.88.0 toolchain
can execute these tests. The canonical MSVC invocation encountered a missing
`link.exe`; that is an environmental failure, not a passing test. No executable
was copied, renamed or otherwise altered to evade Application Control.

Executed local evidence before the initial PR head:

- Provider all-features: 74 library tests (including 20 lifecycle and 26
  transport tests), 11 provider-binary input tests, and doc tests passed.
- Provider no-default-features check passed. Rust 1.88.0 provider Clippy with
  all features/targets and warnings denied passed.
- Full workspace/all-target/all-feature Rust 1.88.0 GNU check passed. The full
  workspace test compiled successfully, ran one API and 42 artifact tests, then
  Application Control blocked the CLI test executable (OS error 4551, never
  executed). The current-stable Clippy tool was separately blocked by that
  policy. Neither invocation is recorded as green; no bypass was attempted.
- Canonical Rust 1.88.0 formatting and whitespace checks passed. Workspace
  metadata remains locked; root, compatibility and fuzz lockfiles are unchanged.
- Native-provider architecture suite passed 23 tests, including the current
  workspace contract. Two additional AST-negative tests compiled, but the final
  25-test executable was blocked by Application Control before execution.
- Full architecture command reached an unchanged pre-existing SSRF gate's
  literal-LF source check, which fails on this CRLF checkout. Both required
  source fragments match after in-memory CRLF normalization; the gate, scanner
  source files and coverage configuration are unchanged from reviewed main.
  This local failure is recorded, not waived or silently repaired in PR A.
- Development-line, scanner corpus (127 cases), both historical salvage
  validators, artifact catalog and exploit catalog passed; their digests are
  unchanged. These catalog checks perform no exploit execution.
- `cargo-deny` and pinned `cargo-semver-checks` are not installed locally; the
  semver command reports that missing prerequisite. The pinned shell audit and
  Linux-only Tarpaulin path are deferred to their existing CI jobs.
  Exact workspace coverage, dependency
  policy, remaining workspace tests, platform checks and final-head CI remain
  pending until recorded in the PR verification receipt.

Thresholds, accepted baseline, omissions, published assets, source version
and protected-main rules are unchanged.

Target and provider traffic ceilings are unchanged by PR A. The existing
provider plan remains at most twelve admitted requests: registration, two
allocations, preflight, at most seven later polls, and cleanup. No additional
target probe, polling retry, deadline extension or scanner capability is added.

## PR B local validation and scope

The following evidence is separate from PR A and from GitHub exact-head CI:

- The provider's 80 library tests, 11 provider-binary input tests and doc tests
  passed with ordinary GNU Rust 1.88.0. Provider all-target/all-feature Clippy
  under that toolchain passed with warnings denied.
- Eight focused scanner diagnostic/accounting tests passed without target
  traffic. Synthetic client response-head tests distinguish status families;
  no active replay/verification regression was introduced for F3.
- The adapter accounting tests compiled, but Windows Application Control
  prevented their execution. They are pending CI execution, not locally green.
- Both focused architecture diagnostic-shape and negative-mutation tests
  passed. They require the exact optional unit-enum fields and reject public
  fields, arbitrary strings and payload-bearing variants.
- Canonical Rust 1.88.0 formatting, the workspace all-feature/all-target check,
  provider and scanner feature-off checks, and the CLI's explicit review-feature
  check passed. Existing feature-off scanner warnings are outside this diff.
- Development-line, corpus, both salvage and both catalog validators passed
  without rewriting their artifacts or digests. Lockfiles, source version,
  coverage baseline, omissions and all network ceilings are unchanged.

The fresh exact-head GitHub runs subsequently passed current-stable Clippy,
workspace execution, Linux coverage, dependency policy and applicable
platform/compatibility checks, as recorded in the [PR B landing receipt](https://github.com/ITherso/termivar/pull/110#issuecomment-5551145983).
That receipt distinguishes the explicit non-PR deploy/matrix workflow skips
and existing Trivy code-scanning baseline-configuration neutral annotation
from the successful filesystem/secret/configuration scan. Local Application
Control, missing MSVC linker and the existing CRLF-only architecture check
limitation were not bypassed or reclassified as local successes.

PR B is landed at `f0b2889c07fe765f8b2f7bdf785725edda209b67`. F3 remains
Deferred / out of scope / unresolved.

## PR C credential-input contract and pending validation

The [shared credential-input contract](../internals/credential-input.md)
documents the implemented file-opening and owned-memory boundaries. Both
loaders use platform no-follow opening without pathname prechecks, then
validate the opened handle. Unix uses the already-locked `libc` 0.2.186
constants for `O_NOFOLLOW | O_NONBLOCK`. Windows uses reparse-point and
directory-handle flags, anonymous security quality of service, and rejects
all reparse attributes and non-regular handles before reads. Other platform
families fail closed for file input. These are final-component guarantees,
not ancestor containment, immutable snapshots, hard-link provenance or a
promise that opening special/network paths makes no external contact.

CLI intake buffers now enter `Zeroizing` ownership before Unicode/size
validation or bounded reads. Fixed initialized read storage covers partial
errors, including bytes written before a reader returns an error. Overflow
and removed LF/CRLF bytes are wiped while owned, and successful constructor
handoff transfers the allocation without an extra intake copy. Downstream
root/principal `PayloadSeed`/`String` ownership is unchanged and outside this
guarantee. Provider input already used zeroizing storage; the removed
line-ending suffix is now wiped before truncation. Neither change claims
erasure of OS environment storage, allocator history, HTTP-library buffers
or every successful downstream copy.

F6 baseline evidence is source inspection, not an executed before-fix
failure. New deterministic input tests compiled with the ordinary local
toolchain, but Application Control blocked execution of the CLI and provider
test binaries. No workaround was used and this is not a local passing result.
The existing three-OS `Tests / Runtime Smoke` matrix now includes focused CLI
and provider input tests; their exact-head CI results and PR C's final
tested/landed SHA remain pending. These steps add no active F3 regression,
target probe or scanner behavior.

The root lockfile adds only three dependency edges (`libc` for each loader and
`zeroize` for CLI intake), with no existing package-version change; nested
lockfiles, release/tag/version state, coverage gates and historical identifiers
remain unchanged. This section is not a final PR C validation or landing receipt.

Additional local PR C evidence, before opening the Draft airlock:

- Canonical Rust 1.88 formatting and whitespace checks passed. The complete
  workspace/all-target/all-feature GNU Rust 1.88 check and provider/scanner/CLI
  feature-off plus explicit input-feature checks passed.
- Three focused architecture tests passed: current provider workspace closure,
  exact server feature set, and the narrow optional Unix-only `libc` edge.
  Other conditional/renamed/local edges are still rejected. Provider and xtask
  GNU Rust 1.88 Clippy passed with warnings denied.
- The optional full-workspace GNU Rust 1.88 Clippy invocation failed on the
  unchanged `ssrf_oast_runtime.rs` `uninlined_format_args` expression. This is
  not a local passing result or an environmental error; it is outside the
  canonical current-stable Clippy job and the PR C diff. The excluded runtime
  was not edited to accommodate it. Current-stable Clippy remains CI-required.
- Locked compatibility/fuzz metadata passed. Repeating offline Cargo metadata
  resolution left all three lockfile hashes unchanged, with no manual lockfile
  edits or version churn.
- Development-line, scanner corpus (127 cases), both salvage and both catalog
  validators passed; all six semantic/version identities remain unchanged.

F6/F7 execution on each supported OS, workspace execution, current-stable
Clippy, coverage and advisory checks require the final-head CI receipt.
