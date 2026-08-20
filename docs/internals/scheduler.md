# Coordinator internals

The `distributed` feature implements a deterministic, bounded state machine
for an explicit in-process host. `WorkerPool` and the cloneable `TaskQueue`
returned by `WorkerPool::task_queue()` share one `Arc<Mutex<_>>`; selection and
assignment therefore occur under the same lock and revision.

This is not a network scheduler service. There is no transport, serialization,
authentication, persistence, background executor, ambient clock, or restart
recovery.

## Command model

Every mutating coordinator method accepts an `expected_revision` and a
caller-supplied monotonic `now_secs`. Before mutation, the state machine checks:

1. the expected revision equals the current revision;
2. logical time has not regressed;
3. counters can advance without overflow;
4. all operation-specific ownership and capacity rules hold; and
5. the prospective transition preserves state invariants.

An error commits neither the next revision nor a partial state change. A
successful mutation increments the revision exactly once. An exact terminal
replay is a typed no-op at the current revision; it does not bypass the revision
check.

```text
register WorkerSpec
        |
enqueue TaskSpec
        |
atomic task + worker selection
        |
TaskLease (worker/task generations + attempt + lease ID + expiry)
        |
start -> complete / fail / cancel
        |
CompletionReceipt -> bounded ResultAggregator
```

## Queue ordering and assignment

The queue is a `BTreeSet` ordered by descending `TaskPriority`, then ascending
enqueue ordinal, then task ID. Worker records live in a `BTreeMap`. Eligibility
requires `Healthy` status, a non-stale caller-supplied heartbeat observation,
and at least one effective slot. Effective capacity uses integer utilization
basis points.

`assign_next_available` performs selection and lease creation atomically. A
specific task or worker can instead be selected through `assign_task` or
`assign_next`, but the same ownership, capacity, TTL, and revision checks
apply. Equal worker scores resolve by lexicographically smallest worker ID.

## Ownership and terminal replay

`TaskLease` binds a task ID, worker ID and generation, task generation,
attempt, lease ID, acquisition time, and expiry. Queued cancellation uses a
`QueuedTaskFence`; `TaskOwnership` carries the appropriate proof. Snapshot and
receipt fields that define ownership are private and exposed through getters,
which prevents struct-literal fabrication through the public API.

These values are structural compare-and-set/idempotency fences within one
caller-enforced logical epoch, not authenticated capabilities. Independently
replayed pools can produce equal values, and the result store cannot establish
receipt provenance. Hosts must not mix tokens across pool instances, restarts,
tenants, or trust boundaries.

`complete_task` retains an exact `CompletionReceipt`. `fail_task` retains its
terminal failure proof when the retry budget is exhausted. Replaying the same
proof returns the retained outcome, while a stale generation, attempt, lease,
worker, record, or byte sequence fails explicitly.

`WorkerTag` is stored and returned as observational metadata only. It does not
participate in eligibility, scoring, or affinity routing.

## Retry, worker loss, and expiry

Retry policy is the fixed `DistributedLimits::max_retries` value, not a
per-call override. A retry increments task generation and retry count, clears
the old lease, and re-enters the ordered queue only after capacity preflight.
Exhaustion terminalizes the task as `Failed`.

The host drives all recovery:

- `recover_expired_leases` applies the same retry/exhaustion policy to expired
  ownership;
- `deregister_worker` and `prune_dead_workers` mark the exact worker generation
  offline and recover its leases;
- `expire_old_tasks` applies task TTL policy; and
- `update_worker` records heartbeat/status/utilization observations.

These calls return bounded summaries. Nothing runs when the host does not call
them, and losing the process loses all state.

## Result retention

`ResultAggregator` owns a separate mutex-protected `BTreeMap`, revision, byte
counter, and `ResultLimits`. A `CompletionReceipt` is required to store bytes.
Same-receipt/same-byte replay is a no-op. For an occupied task ID, the same
receipt with different bytes conflicts and a different receipt returns
`DistributedError::MismatchedResultReceipt`.
For a new task ID, the store cannot establish a receipt's origin or age; that
single-epoch provenance boundary belongs to the host. Aggregation validates all
identifiers, rejects repeated or missing IDs, enforces total bounds, and
returns values in exact request order.

Task records, terminal proofs, and result bytes are retained until their
process disappears; there is no eviction API. Debug projections redact opaque
task targets and result bytes, but getters return them to the caller. IDs,
target references, and result bytes must be treated as host-owned sensitive
data and pre-redacted where required.

Bounds apply per coordinator or result-store instance to retained payloads.
They do not cap caller pre-allocation, returned clones, concurrent calls,
instance count, allocator overhead, or total process memory. Hosts own those
budgets and ordinary in-process OOM/mutex-poison failure handling.

The lifecycle and external boundary are documented in
[Distributed coordination](../distributed.md) and
[ADR 0022](../adr/0022-bound-host-lua-and-distributed-execution.md).
