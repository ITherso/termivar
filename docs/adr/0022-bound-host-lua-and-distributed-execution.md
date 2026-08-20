# ADR 0022: Bound host-owned Lua execution and process-local coordination

- Status: Accepted
- Date: 2026-08-21
- Supersedes: ADR 0020's Lua and distributed scaffold clauses
- Retains: ADR 0020's independent opt-in features and default-runtime quarantine

## Context

ADR 0020 removed Lua and distributed code from broad default features because
neither surface had an honest executable contract. Lua retained metadata but
did not load source; distributed types suggested remote scheduling without a
transport, durable state, or exact failure model. Keeping those descriptions
after implementing bounded host APIs would be as misleading as promoting the
new APIs into a CLI or production service.

Both problems need narrow library boundaries. Lua requires source provenance,
a minimal VM environment, explicit resource controls, and honest limits on
in-process cancellation. Coordination requires ordered state, atomic revisioned
commands, logical ownership fences, bounded retention, and a clear separation
from any multi-process protocol. Neither contract should silently acquire
scanner, plugin, network, filesystem, clock, or deployment authority.

## Decision

### Shared lifecycle and composition

- `lua` and `distributed` are implemented, tested, Experimental host-library
  surfaces. They remain independent opt-in scanner features and have no default
  `venom scan`, `legacy-scan`, CLI, scanner-phase, or plugin caller.
- Their production modules are private and only an exact reviewed facade is
  re-exported from `venom-scanner`. Ownership-bearing task, worker, fence,
  lease, and receipt values keep their fields private and expose bounded
  getters; `StateSnapshot` exposes only aggregate scalar counters.
- CI compiles the two feature slices independently. The architecture gate pins
  their raw feature closures, dependency options, facade and public inventories,
  constants, authority restrictions, and exact production source fingerprints;
  adversarial mutations must make those checks fail.
- The lifecycle label describes evaluated alpha code, not production readiness
  or a stable compatibility promise.

### Lua execution

- The `lua` feature closes over exactly `core`, optional Tokio, and optional
  `mlua`. `mlua` disables default features and enables only vendored Lua 5.4.
- `LuaScript::new_safe` registers bounded UTF-8 text from a caller-approved
  canonical root, rejects traversal and symbolic-link components, detects a
  source change during its read/recheck sequence, and retains an opaque private
  source snapshot. The approved root must remain trusted and non-writable during
  registration; the loader is not a hostile-filesystem TOCTOU boundary.
- Every invocation creates a fresh VM with `StdLib::NONE`, a configured memory
  limit and instruction hook, a text-only chunk, and a private environment.
  The environment exposes only scalar `type`, bounded scalar `emit`, and
  immutable target/payload/ordered-parameter context projections. It exposes no
  OS, I/O, debug, package, coroutine, filesystem, network, process, thread,
  userdata, native callback registration, binary-chunk, or ambient-global API.
- The result projection permits zero or one scalar return: Boolean, integer,
  finite number, or bounded UTF-8 string. Unsupported types, non-finite values,
  invalid UTF-8, multiple returns, and limit violations fail with typed status
  and error values. Caller-provided context, output, and return data are not
  automatically redacted.
- Configuration applies validated configurable and absolute ceilings to source,
  total source, context, VM memory, instructions, hook interval, deadline,
  output, return, scripts, concurrency, and retained history. Limits are per
  registry/execution, not a process-wide memory or allocator guarantee.
- Deadline and cancellation checks are cooperative. A Lua instruction hook
  cannot hard-preempt parser, allocator, native callback, or VM work between
  checks. Execution uses blocking-pool work; dropping the async future does not
  stop that work, so an abandoning host must cancel its retained token. This is
  not process isolation.
- Manifests, results, and receipts retain a deterministic unkeyed
  `source_sha256` plus stable script identity. History omits source, path,
  context, output, and return values, but its digest, identity, status/error,
  and elapsed time remain linkable sensitive metadata rather than a
  confidentiality boundary.
- Registry history is a best-effort bounded ring buffer, not a complete or
  durable audit log. Entry and byte caps evict older receipts, and a receipt
  larger than its configured retention cap is not stored.

### Distributed coordination

- The `distributed` feature has an empty raw dependency closure. It uses
  ordered integer-only process-local state and caller-supplied monotonic logical
  seconds; it reads no ambient clock, randomness, filesystem, network, process,
  or thread authority and defines no serialization implementation.
- `DistributedLimits` and public absolute constants bound retained task,
  active/queued, terminal-reservation, worker, retry, lease/TTL/heartbeat, and
  result/aggregate records and bytes. Limits apply per instance and retained
  payload. Caller pre-allocation, returned clones, concurrent calls, allocator
  overhead/failure, and instance count remain host budgets.
- Every mutating coordinator command checks an expected revision, logical time,
  ownership/capacity, counter overflow, and prospective invariants before one
  atomic revision advance. Selection uses deterministic ordered state and
  integer utilization. Determinism assumes a fixed accepted command order;
  mutex linearization does not choose which concurrent caller wins OS
  scheduling.
- Assignment creates exact task/worker-generation, attempt, lease-ID, and expiry
  fences. Completion/failure require `Running`; retry and all recovery paths
  preflight queue/counter/capacity changes. Terminal replay is a typed no-op only
  at the current revision with the retained proof; start replay additionally
  requires an unexpired lease.
- Leases, queued fences, ownership values, and completion receipts are
  deterministic structural compare-and-set/idempotency tokens within one
  caller-enforced coordinator epoch. They are not authentication, authority,
  cross-instance provenance, or hostile replay resistance. Identically replayed
  independent pools can produce equal tokens, and a standalone result store
  cannot authenticate a new receipt's origin. Hosts must not mix epochs,
  instances, restarts, tenants, or trust domains.
- Worker tags are retained observational metadata only; selection has no
  affinity or capability matching. Opaque target and result bytes remain
  caller-visible through getters. IDs remain visible in diagnostics, so hosts
  pre-redact sensitive identifiers and content.
- Recovery, expiry, heartbeat observations, result storage, and aggregation run
  only when called. There is no background executor, lease renewal, eviction,
  transport, authentication, wire schema, persistence, restart reconciliation,
  exactly-once delivery, or multi-node service.

## Consequences

- Explicit hosts can execute reviewed Lua source and exercise deterministic
  process-local coordination without importing those authorities into either
  scanner runtime.
- Stronger Lua isolation requires a separately supervised process or comparable
  OS boundary with its own IPC, resource, cancellation, and shutdown contract.
- A distributed deployment requires an API-breaking or versioned coordinator
  epoch, authenticated/encrypted transport, durable wire schemas and state,
  replay policy, restart reconciliation, tenant isolation, background work, and
  operational evidence. Serializing the current Rust values ad hoc does not
  create that contract.
- Retained Lua history is best-effort and evicting; distributed terminal/results
  state is non-evicting until process loss. Both are bounded and non-durable.
  Hosts own complete audit/persistence, lifecycle/re-registration, logging and
  redaction, instance/concurrency budgets, and compatibility policy.
- Both public APIs may change before a stable baseline. Adding any repository
  caller or wider authority requires a separate composition and security review.

## Alternatives considered

- **Keep both modules as inert scaffolds.** Rejected because bounded executable
  host contracts now exist and must be documented truthfully.
- **Compose them into the default or legacy scanner.** Rejected because that
  would add execution and state authority without a product policy, CLI
  contract, or compatibility decision.
- **Call the Lua VM a sandbox.** Rejected because in-process hooks and allocator
  limits cannot provide hard preemption or protect the host process from every
  native/runtime failure.
- **Treat Rust lease/receipt values as network capabilities.** Rejected because
  deterministic structural tokens have no authenticated coordinator-instance
  binding or wire provenance.
- **Add serialization and network transport now.** Rejected because transport,
  authentication, version negotiation, durability, epochs, and restart policy
  must be designed together rather than inferred from in-memory types.
