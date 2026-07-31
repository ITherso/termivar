# Scheduler internals

The compiled `distributed` feature currently exposes three in-process building blocks:

- `TaskQueue` stores serialized-friendly `ScanTask` values and keeps a FIFO queue per priority.
- `WorkerPool` owns registered `WorkerNode` values and coordinates task assignment and completion.
- `ResultAggregator` stores task result bytes for later collection.

This is a **Preview control-plane model**, not a networked scheduler service.

## Selection and assignment

`WorkerPool::get_available_worker` filters out offline or full workers, then selects the highest worker score. The score combines status, heartbeat recency, CPU, memory, and effective capacity. Assignment is a separate call that marks a queued task as assigned and increments the selected worker's task count.

```text
register worker
      |
enqueue ScanTask
      |
score available workers
      |
assign task + increment worker count
      |
complete / retry / expire
```

Selection and assignment are not one atomic reservation. A future multi-node scheduler must define leases or another compare-and-set mechanism before concurrent dispatchers can safely share ownership.

## Failure handling

- `retry_task` releases the current worker and requeues until the caller-supplied retry limit is reached.
- `expire_old_tasks` is caller-driven; there is no background timer.
- `update_heartbeat` and `prune_dead_workers` are caller-driven.
- Losing a worker does not currently reassign its tasks automatically.
- Queue and worker state are memory-only and disappear with the process.

## Boundary rules

Workers should receive versioned task data, not `ScanRunner`, plugin registry, or dashboard objects. Transport, authentication, persistence, idempotency keys, leases, and durable result delivery belong outside these in-memory domain primitives.

The production exit criteria are tracked in [Project Status](https://github.com/ITherso/venom/blob/main/PROJECT_STATUS.md) and [Distributed execution](../distributed.md).
