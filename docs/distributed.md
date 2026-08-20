# Distributed coordination

The opt-in `distributed` feature is an Experimental, implemented host-library
contract for bounded deterministic coordination inside one process. Its raw
feature closure is empty, and it has no repository product/runtime or CLI
caller; the repository example is an explicit library host.

It is not a distributed service. The module provides no network transport,
peer authentication, wire encoding, persistence, background timer, process
recovery, consensus, or exactly-once delivery.

## Contract at a glance

| Concern | Current contract |
| --- | --- |
| Build | Explicit `venom-scanner` feature `distributed` |
| Host boundary | Root exports such as `WorkerPool`, `TaskQueue`, `TaskLease`, and `ResultAggregator` |
| Ordering | `BTreeMap`/`BTreeSet` state and stable tie-breaking |
| Time | Monotonic logical seconds supplied by the caller |
| Concurrency | One mutex-protected coordinator state shared by a pool and its task-queue facade |
| Ownership | Worker generation, task generation, attempt, lease ID, and lease expiry |
| Mutation | Expected-revision commands with error-atomic failure |
| Retention | Configured and absolute record/byte ceilings; no eviction |
| Default runtime | No participation in `venom scan`, `legacy-scan`, plugins, or Lua |

## Tasks, workers, and logical time

Hosts admit caller-built `WorkerSpec` and `TaskSpec` values. Task, scan, and
worker identifiers are bounded safe ASCII: letters, digits, `.`, `_`, `:`, and
`-`. A task's `target_ref` is opaque; the coordinator stores and returns it but
never opens, resolves, redacts, or authorizes it. Hosts must pre-redact
identifiers and target references when their disclosure would be sensitive.

Every state-changing coordinator command names both the expected revision and
the caller's current logical second. Regressing time or using a stale revision
fails without changing state. The library does not read `SystemTime` or
`Instant`, start a timer, or advance leases on its own.

`WorkerPool::assign_next_available` atomically chooses the highest-priority
FIFO task and the best eligible worker. Equal worker-selection keys choose the
lexicographically smallest worker ID. Assignment returns a `TaskLease` fenced
by worker generation, task generation, attempt, lease ID, and exact expiry.
`start_task`, `complete_task`, `fail_task`, and leased cancellation require the
current lease. Completion and failure are valid only after the task reaches
`Running`.

`WorkerTag` values are bounded observational metadata. Selection and
eligibility do not inspect them, and `TaskSpec` has no affinity requirements.

Determinism applies to a fixed accepted command order. The mutex linearizes
concurrent callers, but operating-system scheduling does not guarantee which
contender acquires it first. The read-only `get_available_worker(now_secs)`
rejects time earlier than committed logical time but does not advance time.

An exact terminal replay still has to name the coordinator's current revision.
When its ownership proof and retained terminal receipt match, it returns the
same typed result without incrementing counters or rewriting the record. This
is process-local replay handling, not a network idempotency or exactly-once
guarantee. A `start_task` replay is accepted only while its lease is unexpired.

Leases, queued fences, and completion receipts are deterministic structural
tokens for one caller-enforced coordinator epoch. They are not authenticated,
random, or bound to a coordinator instance. Two independently replayed pools
can create equal token values, and a standalone `ResultAggregator` cannot
verify where a receipt originated. Hosts must never mix tokens across
instances or trust boundaries; hostile cross-instance replay resistance would
require an API-breaking epoch or authenticated binding.

## Retry and recovery

`DistributedLimits::max_retries` fixes retry policy for the coordinator. A
failed running task is requeued under a new task generation until that limit is
exhausted, then becomes `Failed`. Requeueing is capacity checked; a command that
cannot preserve the configured queue bound fails atomically.

Recovery is explicit and caller-driven:

- `recover_expired_leases` processes leases whose supplied logical time is at
  or beyond expiry;
- `deregister_worker` and `prune_dead_workers` mark workers offline and recover
  their owned tasks under the same fixed retry policy;
- `expire_old_tasks` terminalizes tasks under the configured task TTL; and
- `update_worker` supplies heartbeat, status, and integer utilization
  observations for one exact worker generation.

No background thread invokes these methods. A heartbeat is an observation, not
proof of task progress, there is no lease-renewal API, and process termination
loses all coordinator state.

## Bounded state

`DistributedLimits` bounds task records, active and queued tasks, terminal
reservations, workers, retry count, lease TTL, task TTL, and heartbeat timeout.
Public `MAX_*` constants add non-configurable hard ceilings. Worker utilization
uses integer basis points rather than floating-point scores.

Terminal task records are retained and have no eviction API. The configured
terminal reservation ensures admitted active work can become terminal without
exceeding its bound; once retained capacity is consumed, new admissions fail.
Callers needing durable retention, pruning, or restart recovery must implement
that policy outside this library and define a separate compatibility contract.

All limits are per instance and cover retained library payloads. They do not
bound caller allocations before a call, returned clones, allocator overhead,
simultaneous operations, the number of registries/pools, or total process
memory. `tasks`, result lookup, and aggregation clone bounded data; one
aggregate may duplicate up to the configured absolute 256 MiB ceiling while
the retained copy remains. Hosts must budget instance count, configured limits,
and concurrency; allocator failure and mutex poisoning remain ordinary
in-process Rust failure modes.

## Completion results

`ResultAggregator` is a separate bounded in-memory store. `store_result`
requires a `CompletionReceipt` and an expected result-store revision. Replaying
the same receipt with identical bytes is idempotent. For an already occupied
task ID, the same receipt with different bytes is conflicting and a different
receipt returns `DistributedError::MismatchedResultReceipt`. The store cannot
authenticate a receipt's origin for a new task ID; the host enforces the
single-epoch boundary. Result count, individual
bytes, total retained bytes, aggregate item count, and aggregate bytes all have
configured and absolute limits.

`aggregate_results` preserves the caller's exact request order. Missing task
IDs and duplicate task IDs are errors. Results are returned as caller-visible
bytes; the module performs no content validation, redaction, encryption, or
serialization. Stored results also have no eviction API.

## Security and integration boundary

A multi-process or multi-node host must separately define authenticated and
encrypted transport, replay protection, tenant isolation, durable command and
result encoding, restart reconciliation, audit logging, and recovery testing.
The Rust types in this feature intentionally have no `serde` implementation or
wire schema. Passing them through an ad hoc serializer does not create a
supported protocol.

See [Scheduler internals](internals/scheduler.md), the [runtime map](internals/runtime-map.md),
and [ADR 0022](adr/0022-bound-host-lua-and-distributed-execution.md).
