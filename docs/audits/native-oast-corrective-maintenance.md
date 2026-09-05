# Native OAST corrective maintenance

This is a repository maintenance record, not an independent security audit or
an exploitability assessment. Static findings were supplied by the maintainer;
each disposition below distinguishes inspection from executed regression proof.

## Reviewed baseline and delivery

- Reviewed and fetched main: `3de3d32f9cb0b6b76cd9f7a3c24ce4557d848b29`.
- Development version: `0.10.0-alpha.2`. GitHub confirms published prerelease
  `v0.10.0-alpha.1`; no alpha.2 release is present.
- Worktree was clean. Open dependency-update PRs and unrelated branches remain
  outside this work.
- PR A branch: `agent/oast-lifecycle-transport-hardening`.
- Final tested/landed SHA: pending. The PR's head, check attribution and landing
  receipt will identify the tested commit; this document does not assert that
  unexecuted checks passed.

## Finding ledger

| ID / source | Disposition | Observed behavior and intended contract | Regression evidence / change / limits |
| --- | --- | --- | --- |
| F1 — `termivar-oast/src/state.rs`, `register_bearer`, `poll_bearer`, `cleanup_bearer`, `SessionState` | Confirmed defect; repair in PR A | Expiration stops acceptance but abandoned sessions remain in the retained-capacity map indefinitely. Acceptance expiry and finite result retention must be separate. | A dropped-registration-response test failed against old behavior with explicitly advanced monotonic time. PR A adds a 120-second result window after acceptance expiry, checked deadline arithmetic and authenticated lazy reclamation over at most 256 retained entries. Results are not erased at the expiry instant while idle. |
| F2 — `termivar-oast/src/server.rs`, `serve_listener`, `serve_connection`, `AppState::admit` | Confirmed defect; repair in PR A | Connection count is bounded, connection lifetime is not explicitly bounded; handler admission occurs after body extraction. | A single benign incomplete-header duplex test failed against old behavior under paused Tokio time. PR A places admission before body extraction and bounds header, request/body, I/O idle and total connection lifetimes. No load test or target application is used. |
| F3 — `web_runtime/ssrf_oast_runtime.rs`, polling phase completion | Deferred; not evaluated or changed | Active SSRF replay/verification behavior is outside this maintenance execution's supported scope. | No synthetic success oracle, active payload dispatch or verification-efficiency repair is claimed. |
| F4 — `termivar-oast/src/client.rs::validate_response_head`, `native_oast_provider.rs::client_failure`, `ssrf_oast_runtime.rs::provider_terminal` | Confirmed by source inspection; unmodified | Unrelated nonexpected statuses and construction/transport failures collapse to an authentication label. | Regression not yet executed. Preserve typed cause without response prose. The public client error enum is exhaustive, so any new variant needs an explicit source-compatibility decision; the core-only semver gate does not prove OAST compatibility. |
| F5 — provider receipt/count assignments in `ssrf_oast_runtime.rs`; permit dispatch accounting | Confirmed by source inspection; unmodified | A failure receipt can exist before budget admission. Receipt-vector length is not the charged HTTP-operation count. | Regression not yet executed. Preserve logical attempt receipts and use authoritative cumulative admission accounting. A possibly-dispatched marker is not proof of server receipt. |
| F6 — both CLI/provider `open_regular_file` implementations | Conditional local-path risk confirmed by inspection; unmodified | Separate pathname inspection and open do not atomically reject a substituted link or establish object identity. | Existing static-link tests do not establish replacement-race resistance. A future fix must state final-component versus ancestor guarantees per platform; no filesystem exploitation or privileged test result is claimed. |
| F7 — CLI `read_environment`, `read_bounded_line_source` | Confirmed intake-buffer defect by inspection; unmodified | Some owned raw buffers can be dropped on oversize/read error before entering a zeroizing wrapper. | Regression not yet executed. Intake-buffer protection does not erase OS environment storage, allocator history, successful downstream copies or HTTP-library buffers. Provider input already uses `Zeroizing` on several corresponding paths. |
| F8 — `PROJECT_STATUS.md`, `docs/DISTRIBUTION.md`, affected provider documentation | Mixed: narrow stale claims and already-corrected statements | PROJECT_STATUS and an installer sentence remain stale. README and distribution release-status sections already distinguish published alpha.1 from development alpha.2. | The already-corrected release descriptions came from `61d08b3`; retain them. PR A updates only lifecycle/transport documentation needed for F1/F2. Broader factual cleanup remains pending. |

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
