# ADR 0020: Quarantine platform and distribution surfaces

- Status: Accepted
- Date: 2026-08-14
- Supersedes: ADR 0015's build-availability inventory
- Retains: ADR 0015's classification axes and ADR 0017's default runtime
- Reporting clause: Superseded by ADR 0021
- Lua and distributed clauses: Superseded by ADR 0022

## Context

The repository retained dashboard, authentication, persistence,
post-exploitation, realtime, reporting, Lua, distributed, API, proxy, and
deployment-shaped code around the deterministic scanner. Several of those
modules were compiled by broad default features even though no repository
runtime called them. Distribution artifacts compounded the ambiguity: a root
Compose stack declared unused databases, default credentials, disabled
security, and listener health checks, while the default container did not
provide that service.

A source file or workspace crate may remain useful to an explicit library host
without being part of the product default. Build reachability, runtime
participation, and distribution support therefore need enforceable boundaries,
not inferred intent.

## Decision

- `venom-scanner` defaults to exactly `core` plus `scanning`. The historical
  ordered scanner, platform models, report renderers, plugins, Lua, and
  distributed workers remain explicit features: `legacy-scanner`,
  `platform-models`, `reporting`, `plugins`, `lua`, and `distributed`.
- `venom-core` defaults to transport-neutral evidence, reasoning, ontology,
  outcome, predicate, and run-report contracts. Historical event and raw
  finding records require its non-default `legacy-contracts` feature, which
  the scanner forwards only for the three consumers that compile them:
  `legacy-scanner`, `platform-models`, and `reporting`. Its unconsumed config,
  HTTP request/response, vulnerability/result, and generic error facades remain
  in that compatibility feature only so the pinned all-features alpha API gate
  stays patch-compatible; they are absent from the default contract.
- The API and proxy remain separate workspace crates. The CLI composes them only
  through its `api-adapter` and `proxy-adapter` features. The API startup hook
  rejects use because no listener is implemented and owns that adapter error
  locally, with no dependency on another workspace crate. The proxy is honestly named
  and implemented as an explicit fixed-upstream TCP relay; it is not a MITM or
  HTTP interception surface.
- `post_exploitation` and `persistence` remain inert library models under
  `platform-models`. This decision does not add execution paths for either.
- The default container remains a non-root CLI image whose command is
  `venom --help`; it exposes no port and carries no listener health check.
  Container publication is a manual, commit-scoped development action, not a
  supported release channel.
- The misleading root Compose stack is removed. PostgreSQL and Redis are not
  provisioned for tests that do not use them, and executable root Compose
  manifests remain forbidden while deployment status is unsupported.
- The repository installer is removed. The existing `v0.9.0-alpha` artifacts
  predate the bounded default runtime and cannot truthfully install the current
  source contract. A future installer requires a remediated release tag and
  must verify the exact archive against that release's SHA-256 manifest before
  extraction; no package-manager or container-registry channel is claimed.
- Architecture and CI checks bind the Cargo feature graph to exact module gates,
  exercise opt-in features independently, and inspect the container's
  inert/non-root configuration.

## Consequences

- Default builds no longer imply that unwired platform models or extension
  runtimes participate in `venom scan`.
- Optional source-level APIs remain available for explicit hosts. Each
  surface's documented lifecycle—Unsupported, Experimental, Preview, or
  Legacy—is part of its public contract; this decision does not promote them
  to one uniform maturity level.
- Removing historical TLS/certificate dependencies from the relay reduces both
  build surface and false security claims.
- A future API service, intercepting proxy, deployment stack, or package channel
  requires a new executable contract, tests, lifecycle policy, and an explicit
  architecture decision; restoring a manifest or broad default feature is not
  sufficient.

## Alternatives considered

- **Delete every unwired module.** Rejected because some data models and
  host-only adapters remain useful Experimental, Legacy, or Preview APIs;
  explicit quarantine makes each status truthful without pretending it runs.
- **Keep one broad `full` or default feature as the product boundary.** Rejected
  because it conflates independent authorities and makes dependency additions
  silently change the default runtime.
- **Preserve the Compose stack as an example.** Rejected because executable
  manifests with default credentials and nonexistent health semantics are read
  as runnable guidance even when labelled experimental.
- **Install through guessed package or container channels.** Rejected because no
  such maintained publication contract exists.
